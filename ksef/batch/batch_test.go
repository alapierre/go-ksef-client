package batch

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/alapierre/go-ksef-client/ksef/util"
)

// templateInvoiceSource generuje faktury z szablonu "w locie"
// i implementuje InvoiceSource. Przy okazji zapamiętuje SHA-256
// dla każdej faktury, żeby test mógł to porównać z wynikiem batcha.
type templateInvoiceSource struct {
	templatePath string
	count        int
	idx          int

	// expected przechowuje oczekiwane hashe w kolejności Next().
	expected []InvoiceHash
}

func newTemplateInvoiceSource(templatePath string, count int) *templateInvoiceSource {
	return &templateInvoiceSource{
		templatePath: templatePath,
		count:        count,
		expected:     make([]InvoiceHash, 0, count),
	}
}

func (s *templateInvoiceSource) Next() (*InvoiceItem, error) {
	if s.idx >= s.count {
		return nil, io.EOF
	}

	i := s.idx

	buyerNip := fmt.Sprintf("%010d", s.count+i)

	xmlBytes, err := util.ReplacePlaceholdersInXML(s.templatePath, map[string]any{
		"NIP":        "1234567890",
		"ISSUE_DATE": time.Now().AddDate(0, 0, i%30),
		"BUYER_NIP":  buyerNip,
	})
	if err != nil {
		return nil, fmt.Errorf("ReplacePlaceholdersInXML failed (i=%d): %w", i, err)
	}

	sum := sha256.Sum256(xmlBytes)
	hash := make([]byte, len(sum))
	copy(hash, sum[:])

	fileName := fmt.Sprintf("invoice_%04d.xml", i)

	s.expected = append(s.expected, InvoiceHash{
		ID:       fileName,
		FileName: fileName,
		SHA256:   hash,
	})

	item := &InvoiceItem{
		ID:       fileName,
		FileName: fileName,
		XML:      xmlBytes,
	}

	s.idx++
	return item, nil
}

func TestBuildBatchFromSource_TemplateInvoices(t *testing.T) {
	// Ilość faktur do wygenerowania.
	const invoiceCount = 2000

	// Limit wielkości części – powinno wymusić kilka partów.
	const maxPartSize = 256 * 1024 // 256 KiB

	tmpDir := t.TempDir()
	templatePath := filepath.Join("..", "..", "invoice_fa_3_type.xml")

	src := newTemplateInvoiceSource(templatePath, invoiceCount)

	cfg := BatchConfig{
		OutputDir:       tmpDir,
		MaxPartSize:     maxPartSize,
		TempFilePattern: "test-batch-*.zip",
		CleanupPlainZip: false,
	}

	result, err := BuildBatchFromSource(cfg, src)
	if err != nil {
		t.Fatalf("BuildBatchFromSource returned error: %v", err)
	}
	if result == nil {
		t.Fatalf("BuildBatchFromSource returned nil result")
	}

	t.Logf("ZIP path: %s, size: %d bytes", result.ZipPath, result.ZipSize)
	t.Logf("Parts: %d, InvoiceHashes: %d", len(result.Parts), len(result.InvoiceHashes))

	// 1) Liczba hashy = liczba faktur.
	if len(result.InvoiceHashes) != invoiceCount {
		t.Errorf("expected %d invoice hashes, got %d", invoiceCount, len(result.InvoiceHashes))
	}

	// 2) Źródło wygenerowało dokładnie tyle hashy, ile faktur.
	if len(src.expected) != invoiceCount {
		t.Fatalf("templateInvoiceSource expected %d hashes, has %d",
			invoiceCount, len(src.expected))
	}

	// 3) Przy 2000 faktur i maxPartSize 256 KiB ZIP powinien być pocięty na kilka części.
	if len(result.Parts) < 2 {
		t.Errorf("expected ZIP to be split into multiple parts, but got only %d part(s)", len(result.Parts))
	}

	// 4) Porównanie hashy: to, co policzył batch (result.InvoiceHashes),
	// musi się zgadzać z tym, co policzyło źródło (src.expected),
	// po indeksie (kolejność Next()).
	if len(result.InvoiceHashes) != len(src.expected) {
		t.Fatalf("mismatch between InvoiceHashes (%d) and expected (%d)",
			len(result.InvoiceHashes), len(src.expected))
	}

	for i := range src.expected {
		got := result.InvoiceHashes[i]
		exp := src.expected[i]

		if !bytes.Equal(got.SHA256, exp.SHA256) {
			t.Errorf("hash mismatch for invoice index %d (FileName=%s)", i, exp.FileName)
		}
	}

	// 5) Spójność partów + klucz AES.
	if len(result.AESKey) == 0 {
		t.Errorf("AESKey is empty")
	}

	var totalPlain int64
	for _, p := range result.Parts {
		if p.PlainSize <= 0 {
			t.Errorf("part %d has non-positive PlainSize: %d", p.Index, p.PlainSize)
		}
		if p.PlainSize > maxPartSize {
			t.Errorf("part %d exceeds MaxPartSize: %d > %d", p.Index, p.PlainSize, maxPartSize)
		}
		if p.CipherSize <= 0 {
			t.Errorf("part %d has non-positive CipherSize: %d", p.Index, p.CipherSize)
		}
		if len(p.IV) == 0 {
			t.Errorf("part %d has empty IV", p.Index)
		}
		totalPlain += p.PlainSize
	}

	if totalPlain != result.ZipSize {
		t.Errorf("sum of PlainSize in parts (%d) != ZipSize (%d)", totalPlain, result.ZipSize)
	}
}
