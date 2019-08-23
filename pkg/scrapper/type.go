package scrapper

import (
	"github.com/danieloliveira079/php-composer-scanner/pkg/storage"
	"github.com/danieloliveira079/php-composer-scanner/pkg/vulnerability"
	"time"
)

type Scrapper interface {
	Run(storage storage.Storage) (Results, error)
}

type ScrapperService interface {
	New(scrapper Scrapper)
	Scrape() (Results, error)
}

type Results struct {
	ScrappedAt      time.Time
	Vulnerabilities []vulnerability.Vulnerability
}
