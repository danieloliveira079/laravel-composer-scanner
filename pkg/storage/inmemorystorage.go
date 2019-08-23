package storage

import (
	"github.com/danieloliveira079/php-composer-scanner/pkg/vulnerability"
)

type InMemoryStorage struct {
	records map[string]vulnerability.Vulnerability
}

func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		records: map[string]vulnerability.Vulnerability{},
	}
}

func (j *InMemoryStorage) Add(vulnerability vulnerability.Vulnerability) {
	j.records[vulnerability.PackageName] = vulnerability
}

func (j *InMemoryStorage) GetAll() []vulnerability.Vulnerability {
	var results []vulnerability.Vulnerability

	for _, record := range j.records {
		results = append(results, record)
	}

	return results
}
