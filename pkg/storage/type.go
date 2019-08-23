package storage

import "github.com/danieloliveira079/php-composer-scanner/pkg/vulnerability"

type Storage interface {
	Add(vulnerability vulnerability.Vulnerability)
	GetAll() []vulnerability.Vulnerability
}
