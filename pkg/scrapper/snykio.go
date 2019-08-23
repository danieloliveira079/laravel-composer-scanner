package scrapper

import (
	"errors"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/danieloliveira079/php-composer-scanner/pkg/storage"
	"github.com/danieloliveira079/php-composer-scanner/pkg/vulnerability"
	"log"
	"net/http"
	"strings"
	"time"
)

const SnykioURI = "https://snyk.io/vuln/page/%d?type=composer"

var (
	errorStorageIsNil = errors.New("the scrapper does not have a storage")
)

type Snykio struct {
	TargetURI string
	Storage   storage.Storage
}

type SnykioDocument struct {
	*goquery.Document
}

func NewSnykioScrapper(targetURI string, storage storage.Storage) (*Snykio, error) {
	if len(targetURI) == 0 {
		targetURI = SnykioURI
		log.Println("target URI not informed, using default", SnykioURI)
	}

	if storage == nil {
		return nil, errorStorageIsNil
	}

	return &Snykio{TargetURI: targetURI, Storage: storage}, nil
}

func (s *Snykio) Run(storage storage.Storage) (Results, error) {
	results := Results{
		ScrappedAt:      time.Now(),
		Vulnerabilities: []vulnerability.Vulnerability{},
	}

	err := s.ScrapeURI(1, 0)
	if err != nil {
		return results, err
	}

	for _, v := range s.Storage.GetAll() {
		results.Vulnerabilities = append(results.Vulnerabilities, v)
	}

	return results, err
}

func (s *Snykio) ScrapeURI(startPage, endPage int) error {
	if startPage == 0 {
		startPage = 1
	}

	if endPage == 0 {
		endPage = 1000
	}

	currentPage := startPage
	for {
		document, err := s.ScrapePage(currentPage)
		if err != nil {
			return err
		}

		vulnerabilities := document.ToVulnerabilities()
		if len(vulnerabilities) == 0 {
			return nil
		}

		for _, v := range vulnerabilities {
			s.Storage.Add(v)
		}

		if currentPage == endPage {
			return nil
		}

		currentPage++
	}
}

func (s *Snykio) ScrapePage(pageNumber int) (*SnykioDocument, error) {
	pageURL := fmt.Sprintf(s.TargetURI, pageNumber)
	res, err := http.Get(pageURL)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, err
	}

	return &SnykioDocument{doc}, nil
}

func (s *SnykioDocument) ToVulnerabilities() []vulnerability.Vulnerability {
	var vulnerabilities []vulnerability.Vulnerability

	table := s.Document.Find(".table--comfortable tbody tr")
	if len(table.Nodes) == 0 {
		return vulnerabilities
	}

	table.Each(func(i int, rows *goquery.Selection) {
		level := rows.Find(".severity-list__item-text").Text()
		title := rows.Find("span a strong").Text()
		versions := rows.Find(".semver").Text()
		affects := rows.Find(".list-vulns__item__package__name a").Text()
		published := strings.TrimSpace(rows.Find("td.l-align-right").Text())

		parsedVulnerability := vulnerability.Vulnerability{
			Level:       level,
			Type:        title,
			Versions:    s.ParseVersions(versions),
			PackageName: affects,
			Published:   published,
		}

		vulnerabilities = append(vulnerabilities, parsedVulnerability)
	})

	return vulnerabilities
}

func (s *SnykioDocument) ParseVersions(versions string) (result []string) {
	items := strings.Split(versions, ",")

	for _, v := range items {
		result = append(result, strings.TrimSpace(v))
	}

	return result
}
