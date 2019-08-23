package storage

import (
	"github.com/danieloliveira079/php-composer-scanner/pkg/vulnerability"
	"github.com/stretchr/testify/require"
	"reflect"
	"testing"
)

func TestInMemoryStorage_Add(t *testing.T) {
	dummyVulnerability := vulnerability.Vulnerability{}

	storage := NewInMemoryStorage()
	storage.Add(dummyVulnerability)

	t.Run("Should Add Vulnerability to Storage", func(t *testing.T) {
		stored := storage.GetAll()

		require.NotEmpty(t, stored)
		require.Equal(t, true, reflect.DeepEqual(dummyVulnerability, stored[0]))
	})
}

func TestInMemoryStorage_GetAll(t *testing.T) {
	dummyVulnerabilities := []vulnerability.Vulnerability{
		{
			Level:       "M",
			Type:        "SQL Injection",
			Versions:    []string{"5.20.12"},
			PackageName: "adodb/adodb-php",
			Published:   "30 Apr, 2018",
		},
		{
			Level:       "M",
			Type:        "Cross-site Scripting (XSS)",
			Versions:    []string{"2.20.0"},
			PackageName: "aheinze/cockpit",
			Published:   "21 Oct, 2018",
		},
	}

	storage := NewInMemoryStorage()

	for _, v := range dummyVulnerabilities {
		storage.Add(v)
	}

	t.Run("Should Return Two Vulnerabilities", func(t *testing.T) {
		stored := storage.GetAll()
		require.NotEmpty(t, stored)
		require.Equal(t, len(stored), len(dummyVulnerabilities))
	})
}
