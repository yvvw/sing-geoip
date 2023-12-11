package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-github/v45/github"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/inserter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/exceptions"
	"github.com/sirupsen/logrus"
)

var githubClient *github.Client

func init() {
	accessToken, loaded := os.LookupEnv("ACCESS_TOKEN")
	if !loaded {
		githubClient = github.NewClient(nil)
		return
	}
	transport := &github.BasicAuthTransport{
		Username: accessToken,
	}
	githubClient = github.NewClient(transport.Client())
}

func setActionOutput(name string, content string) {
	outputPath, exists := os.LookupEnv("GITHUB_OUTPUT")
	if exists {
		_ = os.WriteFile(outputPath, []byte(name+"="+content+"\n"), fs.ModeAppend)
	}
}

func getLatestRelease(from string) (*github.RepositoryRelease, error) {
	names := strings.SplitN(from, "/", 2)
	latestRelease, _, err := githubClient.Repositories.GetLatestRelease(context.Background(), names[0], names[1])
	if err != nil {
		return nil, err
	}
	return latestRelease, err
}

func download(url *string) ([]byte, error) {
	logrus.Info("download ", *url)
	response, err := http.Get(*url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	return io.ReadAll(response.Body)
}

func downloadGeoIp(release *github.RepositoryRelease, fileName string) ([]byte, error) {
	geoipAsset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == fileName
	})
	if geoipAsset == nil {
		return nil, exceptions.New(fileName+" not found in upstream release ", release.Name)
	}
	geoipChecksumAsset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == fileName+".sha256sum"
	})
	if geoipChecksumAsset == nil {
		return nil, exceptions.New(fileName+".sha256sum not found in upstream release ", release.Name)
	}
	data, err := download(geoipAsset.BrowserDownloadURL)
	if err != nil {
		return nil, err
	}
	remoteChecksum, err := download(geoipChecksumAsset.BrowserDownloadURL)
	if err != nil {
		return nil, err
	}
	checksum := sha256.Sum256(data)
	if hex.EncodeToString(checksum[:]) != string(remoteChecksum[:64]) {
		return nil, exceptions.New("checksum mismatch")
	}
	return data, nil
}

func parse(binary []byte) (metadata maxminddb.Metadata, countryMap map[string][]*net.IPNet, err error) {
	database, err := maxminddb.FromBytes(binary)
	if err != nil {
		return
	}
	metadata = database.Metadata
	networks := database.Networks(maxminddb.SkipAliasedNetworks)
	countryMap = make(map[string][]*net.IPNet)
	var country geoip2.Enterprise
	var ipNet *net.IPNet
	for networks.Next() {
		ipNet, err = networks.Network(&country)
		if err != nil {
			return
		}
		var code string
		if country.Country.IsoCode != "" {
			code = strings.ToLower(country.Country.IsoCode)
		} else if country.RegisteredCountry.IsoCode != "" {
			code = strings.ToLower(country.RegisteredCountry.IsoCode)
		} else if country.RepresentedCountry.IsoCode != "" {
			code = strings.ToLower(country.RepresentedCountry.IsoCode)
		} else if country.Continent.Code != "" {
			code = strings.ToLower(country.Continent.Code)
		} else {
			continue
		}
		countryMap[code] = append(countryMap[code], ipNet)
	}
	err = networks.Err()
	return
}

func newWriter(metadata maxminddb.Metadata, codes []string) (*mmdbwriter.Tree, error) {
	return mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "sing-geoip",
		Languages:               codes,
		IPVersion:               int(metadata.IPVersion),
		RecordSize:              int(metadata.RecordSize),
		Inserter:                inserter.ReplaceWith,
		DisableIPv4Aliasing:     true,
		IncludeReservedNetworks: true,
	})
}

func writeData(writer *mmdbwriter.Tree, dataMap map[string][]*net.IPNet, output string, codes []string) error {
	if len(codes) == 0 {
		codes = make([]string, 0, len(dataMap))
		for code := range dataMap {
			codes = append(codes, code)
		}
	}
	sort.Strings(codes)
	codeMap := make(map[string]bool)
	for _, code := range codes {
		codeMap[code] = true
	}
	for code, data := range dataMap {
		if !codeMap[code] {
			continue
		}
		for _, item := range data {
			err := writer.Insert(item, mmdbtype.String(code))
			if err != nil {
				return err
			}
		}
	}
	outputFile, err := os.Create(output)
	if err != nil {
		return err
	}
	defer outputFile.Close()
	_, err = writer.WriteTo(outputFile)
	return err
}

func generateIPList(ipMap map[string][]*net.IPNet, outputFileName string) error {
	outputFile, err := os.Create(outputFileName)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	var list []string
	for key := range ipMap {
		list = append(list, key)
	}
	sort.Strings(list)

	_, err = outputFile.WriteString(strings.Join(list, "\n"))

	return err
}

func generateGeoIp(release *github.RepositoryRelease, inputFileName string, outputFileName string, outputCNFileName string, ruleSetDir string) error {
	binary, err := downloadGeoIp(release, inputFileName)
	if err != nil {
		return err
	}
	metadata, ipMap, err := parse(binary)
	if err != nil {
		return err
	}

	if ruleSetDir != "" {
		_ = os.RemoveAll(ruleSetDir)
		err = os.MkdirAll(ruleSetDir, 0o755)
		if err != nil {
			return err
		}

		for countryCode, ipNets := range ipMap {
			var headlessRule option.DefaultHeadlessRule
			headlessRule.IPCIDR = make([]string, 0, len(ipNets))
			for _, cidr := range ipNets {
				headlessRule.IPCIDR = append(headlessRule.IPCIDR, cidr.String())
			}
			var plainRuleSet option.PlainRuleSet
			plainRuleSet.Rules = []option.HeadlessRule{
				{
					Type:           constant.RuleTypeDefault,
					DefaultOptions: headlessRule,
				},
			}
			srsPath, _ := filepath.Abs(filepath.Join(ruleSetDir, "geoip-"+countryCode+".srs"))
			outputRuleSet, err := os.Create(srsPath)
			if err != nil {
				return err
			}
			err = srs.Write(outputRuleSet, plainRuleSet)
			if err != nil {
				_ = outputRuleSet.Close()
				return err
			}
			_ = outputRuleSet.Close()
		}
	}

	err = generateIPList(ipMap, strings.Split(outputFileName, ".")[0]+".txt")
	if err != nil {
		return err
	}

	codes := make([]string, 0, len(ipMap))
	for code := range ipMap {
		codes = append(codes, code)
	}
	writer, err := newWriter(metadata, codes)
	if err != nil {
		return err
	}
	err = writeData(writer, ipMap, outputFileName, nil)
	if err != nil {
		return err
	}

	codes = []string{"cn"}
	writer, err = newWriter(metadata, codes)
	if err != nil {
		return err
	}
	err = writeData(writer, ipMap, outputCNFileName, []string{"cn"})
	if err != nil {
		return err
	}

	return nil
}

func main() {
	source := "soffchen/geoip"
	input := "Country.mmdb"
	output := "geoip.db"
	outputCN := "geoip-cn.db"

	destination := "yvvw/sing-geoip"

	sourceRelease, err := getLatestRelease(source)
	if err != nil {
		logrus.Fatal(err)
	}
	destinationRelease, err := getLatestRelease(destination)
	if err != nil {
		logrus.Warn("missing destination latest release")
	} else {
		if os.Getenv("NO_SKIP") != "true" && strings.Contains(*destinationRelease.TagName, *sourceRelease.TagName) {
			logrus.Info("already latest")
			setActionOutput("skip", "true")
			return
		}
	}

	err = generateGeoIp(sourceRelease, input, output, outputCN, "rule-set")
	if err != nil {
		logrus.Fatal(err)
	}

	tagName := *sourceRelease.TagName
	setActionOutput("tag", tagName)
}
