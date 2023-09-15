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
	"sort"
	"strings"

	"github.com/google/go-github/v45/github"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/inserter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
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
		os.WriteFile(outputPath, []byte(name+"="+content+"\n"), fs.ModeAppend)
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
		return nil, E.New(fileName+" not found in upstream release ", release.Name)
	}
	geoipChecksumAsset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == fileName+".sha256sum"
	})
	if geoipChecksumAsset == nil {
		return nil, E.New(fileName+".sha256sum not found in upstream release ", release.Name)
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
		return nil, E.New("checksum mismatch")
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

func generateGeoIp(release *github.RepositoryRelease, inputFileName string, outputFileName string, outputCNFileName string) error {
	binary, err := downloadGeoIp(release, inputFileName)
	if err != nil {
		return err
	}
	metadata, countryMap, err := parse(binary)
	if err != nil {
		return err
	}

	codes := make([]string, 0, len(countryMap))
	for code := range countryMap {
		codes = append(codes, code)
	}
	writer, err := newWriter(metadata, codes)
	if err != nil {
		return err
	}
	err = writeData(writer, countryMap, outputFileName, nil)
	if err != nil {
		return err
	}

	codes = []string{"cn"}
	writer, err = newWriter(metadata, codes)
	if err != nil {
		return err
	}
	err = writeData(writer, countryMap, outputCNFileName, []string{"cn"})
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

	err = generateGeoIp(sourceRelease, input, output, outputCN)
	if err != nil {
		logrus.Fatal(err)
	}

	tagName := *sourceRelease.TagName
	setActionOutput("tag", tagName)
}
