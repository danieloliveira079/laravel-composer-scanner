package scrapper

import (
	"github.com/danieloliveira079/php-composer-scanner/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_Snykio_ScrapePage(t *testing.T) {
	t.Run("Should Scrape Single Page", func(t *testing.T) {
		scrapper, err := NewSnykioScrapper("", storage.NewInMemoryStorage())
		require.Nil(t, err)

		snykioDoc, err := scrapper.ScrapePage(1)
		require.Nil(t, err)
		require.NotNil(t, snykioDoc.Document)
	})

	t.Run("Should Throw Error Scraping Non Existing Page", func(t *testing.T) {
		scrapper, err := NewSnykioScrapper("dummyURL", storage.NewInMemoryStorage())
		require.Nil(t, err)

		_, err = scrapper.ScrapePage(1)
		require.NotNil(t, err)
	})
}

func Test_SnykioDocument_ParseDocument(t *testing.T) {
	scrapper, err := NewSnykioScrapper("", storage.NewInMemoryStorage())
	require.Nil(t, err)

	snykioDoc, err := scrapper.ScrapePage(1)
	require.Nil(t, err)

	vulnerabilities := snykioDoc.ToVulnerabilities()
	require.NotEmpty(t, vulnerabilities)
}

func TestSnykio_ScrapeURI(t *testing.T) {
	t.Run("Should Scrape and Store 30 Vulnerabilities", func(t *testing.T) {
		scrapper, err := NewSnykioScrapper("", storage.NewInMemoryStorage())
		require.Nil(t, err)

		err = scrapper.ScrapeURI(1, 1)
		require.Nil(t, err)
		vulnerabilities := scrapper.Storage.GetAll()
		assert.Equal(t, 30, len(vulnerabilities))
	})

	t.Run("Should Scrape and Store 60 Vulnerabilities", func(t *testing.T) {
		scrapper, err := NewSnykioScrapper("", storage.NewInMemoryStorage())
		require.Nil(t, err)

		err = scrapper.ScrapeURI(1, 2)
		require.Nil(t, err)
		vulnerabilities := scrapper.Storage.GetAll()
		assert.Equal(t, 60, len(vulnerabilities))
	})
}
