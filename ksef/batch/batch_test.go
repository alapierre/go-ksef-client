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

// templateInvoiceSource generuje faktury z szablonu "w locie" i implementuje InvoiceSource.
// Dodatkowo liczy SHA-256 i:
//   - wstawia je do InvoiceItem.SHA256 (używane przez BuildBatchFromSource),
//   - zapamiętuje w expectedSHA, żeby test mógł porównać wyniki.
type templateInvoiceSource struct {
	templatePath string
	count        int
	idx          int

	// expectedSHA przechowuje oczekiwane SHA-256 w kolejności Next().
	expectedSHA [][]byte
}

func newTemplateInvoiceSource(templatePath string, count int) *templateInvoiceSource {
	return &templateInvoiceSource{
		templatePath: templatePath,
		count:        count,
		expectedSHA:  make([][]byte, 0, count),
	}
}

func (s *templateInvoiceSource) Next() (*InvoiceItem, error) {
	if s.idx >= s.count {
		return nil, io.EOF
	}

	i := s.idx

	buyerNip := fmt.Sprintf("%010d", s.count+i)

	xmlBytes, err := util.ReplacePlaceholdersInXML(s.templatePath, map[string]any{
		"NIP":        "1234567890",                   // stały NIP sprzedawcy
		"ISSUE_DATE": time.Now().AddDate(0, 0, i%30), // różne daty
		"BUYER_NIP":  buyerNip,                       // różne NIP-y nabywców
	})
	if err != nil {
		return nil, fmt.Errorf("ReplacePlaceholdersInXML failed (i=%d): %w", i, err)
	}

	sum := sha256.Sum256(xmlBytes)
	hash := make([]byte, len(sum))
	copy(hash, sum[:])

	fileName := fmt.Sprintf("invoice_%04d.xml", i)

	// zapamiętujemy hash jako „expected”
	s.expectedSHA = append(s.expectedSHA, hash)

	item := &InvoiceItem{
		ID:       fileName,
		FileName: fileName,
		XML:      xmlBytes,
		SHA256:   hash, // KLUCZOWE: BuildBatchFromSource użyje tego zamiast liczyć SHA ponownie
	}

	s.idx++
	return item, nil
}

func TestBuildBatchFromSource_TemplateInvoices(t *testing.T) {
	// Ilość faktur do wygenerowania (duża, żeby wymusić podział ZIP-a).
	const invoiceCount = 2000

	// Limit wielkości części – 256 KiB powinno dać kilka partów.
	const maxPartSize = 256 * 1024 // 256 KiB

	tmpDir := t.TempDir()
	templatePath := filepath.Join("..", "..", "invoice_fa_3_type.xml")

	src := newTemplateInvoiceSource(templatePath, invoiceCount)

	cfg := BatchConfig{
		OutputDir:       tmpDir,
		MaxPartSize:     maxPartSize,
		TempFilePattern: "test-batch-*.zip",
		CleanupPlainZip: false, // możesz dać true, jeśli nie chcesz zostawiać ZIP-a
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
	if len(src.expectedSHA) != invoiceCount {
		t.Fatalf("templateInvoiceSource expected %d hashes, has %d",
			invoiceCount, len(src.expectedSHA))
	}

	// 3) ZIP przy takim rozmiarze powinien być podzielony na kilka części.
	if len(result.Parts) < 2 {
		t.Errorf("expected ZIP to be split into multiple parts, but got only %d part(s)", len(result.Parts))
	}

	// 4) Porównanie hashy: to, co policzyło źródło (expectedSHA),
	// musi się zgadzać z tym, co trafiło do InvoiceHashes.
	if len(result.InvoiceHashes) != len(src.expectedSHA) {
		t.Fatalf("mismatch between InvoiceHashes (%d) and expectedSHA (%d)",
			len(result.InvoiceHashes), len(src.expectedSHA))
	}

	for i := range src.expectedSHA {
		got := result.InvoiceHashes[i].SHA256
		exp := src.expectedSHA[i]

		if !bytes.Equal(got, exp) {
			t.Errorf("hash mismatch for invoice index %d (FileName=%s)", i, result.InvoiceHashes[i].FileName)
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
