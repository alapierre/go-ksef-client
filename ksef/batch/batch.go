// Package batch provides helpers for building KSeF batch ZIPs,
// splitting them into <=100MB parts (before encryption) and encrypting
// each part with AES-256-CBC (PKCS#7).
package batch

import (
	"archive/zip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/alapierre/go-ksef-client/ksef/aes"
)

// BuildBatchFromSource builds a single ZIP package by pulling invoices
// from the given InvoiceSource, then splits this ZIP into parts <= MaxPartSize
// and encrypts each part. This is the main, flexible entry point – the source
// may be backed by files, DB records, HTTP multipart, template generator, etc.
//
// Behavior regarding SHA-256:
//   - If InvoiceItem.SHA256 is non-empty, it is used directly (copied).
//   - Otherwise, SHA-256 is computed from InvoiceItem.XML.
func BuildBatchFromSource(cfg BatchConfig, src InvoiceSource) (*BatchResult, error) {
	if cfg.OutputDir == "" {
		cfg.OutputDir = os.TempDir()
	}
	if err := os.MkdirAll(cfg.OutputDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating output dir: %w", err)
	}

	if cfg.MaxPartSize <= 0 {
		cfg.MaxPartSize = 100 * 1024 * 1024 // default: 100 MiB
	}
	if cfg.TempFilePattern == "" {
		cfg.TempFilePattern = "ksef-batch-*.zip"
	}

	// Step 1: build a single ZIP with all invoices from the source.
	tmpZipFile, err := os.CreateTemp(cfg.OutputDir, cfg.TempFilePattern)
	if err != nil {
		return nil, fmt.Errorf("create temp zip: %w", err)
	}
	// If something goes wrong later and CleanupPlainZip is enabled,
	// try to remove the plain ZIP.
	defer func() {
		if err != nil && cfg.CleanupPlainZip {
			_ = os.Remove(tmpZipFile.Name())
		}
	}()

	zipWriter := zip.NewWriter(tmpZipFile)

	var invoiceHashes []InvoiceHash
	index := 0

	for {
		item, srcErr := src.Next()
		if srcErr == io.EOF {
			break
		}
		if srcErr != nil {
			_ = zipWriter.Close()
			_ = tmpZipFile.Close()
			return nil, fmt.Errorf("invoice source error: %w", srcErr)
		}

		if len(item.XML) == 0 {
			_ = zipWriter.Close()
			_ = tmpZipFile.Close()
			return nil, fmt.Errorf("invoice %d (%s) has empty XML", index, item.ID)
		}

		// Decide where to get SHA-256 from:
		// - use precomputed item.SHA256 if provided,
		// - otherwise compute SHA-256 from item.XML.
		var hash []byte
		if len(item.SHA256) > 0 {
			hash = make([]byte, len(item.SHA256))
			copy(hash, item.SHA256)
		} else {
			sum := sha256.Sum256(item.XML)
			hash = make([]byte, len(sum))
			copy(hash, sum[:])
		}

		zipName := item.FileName
		if zipName == "" {
			base := item.ID
			if base == "" {
				base = fmt.Sprintf("invoice_%06d.xml", index+1)
			} else {
				base = filepath.Base(base)
			}
			zipName = fmt.Sprintf("%06d_%s", index+1, base)
		}

		w, createErr := zipWriter.Create(zipName)
		if createErr != nil {
			_ = zipWriter.Close()
			_ = tmpZipFile.Close()
			return nil, fmt.Errorf("create zip entry for %q: %w", zipName, createErr)
		}
		if _, writeErr := w.Write(item.XML); writeErr != nil {
			_ = zipWriter.Close()
			_ = tmpZipFile.Close()
			return nil, fmt.Errorf("write zip entry for %q: %w", zipName, writeErr)
		}

		invoiceHashes = append(invoiceHashes, InvoiceHash{
			ID:       item.ID,
			FileName: zipName,
			SHA256:   hash,
		})

		index++
	}

	if index == 0 {
		_ = zipWriter.Close()
		_ = tmpZipFile.Close()
		return nil, fmt.Errorf("no invoices produced by source")
	}

	if err := zipWriter.Close(); err != nil {
		_ = tmpZipFile.Close()
		return nil, fmt.Errorf("close zip writer: %w", err)
	}
	if err := tmpZipFile.Sync(); err != nil {
		_ = tmpZipFile.Close()
		return nil, fmt.Errorf("sync zip file: %w", err)
	}
	if err := tmpZipFile.Close(); err != nil {
		return nil, fmt.Errorf("close zip file: %w", err)
	}

	// Step 2: split and encrypt the ZIP file.
	return buildBatchFromZip(cfg, tmpZipFile.Name(), invoiceHashes)
}

// BatchConfig defines configuration for building a KSeF batch package.
type BatchConfig struct {
	// OutputDir is a directory where the temporary ZIP and encrypted parts
	// will be written. If empty, os.TempDir() is used.
	OutputDir string

	// MaxPartSize is the maximum size of a single part BEFORE encryption.
	// If zero or negative, a default of 100 MiB is used.
	MaxPartSize int64

	// TempFilePattern is a pattern for os.CreateTemp when creating the ZIP.
	// If empty, "ksef-batch-*.zip" is used.
	TempFilePattern string

	// CleanupPlainZip indicates whether the plain ZIP file should be removed
	// after the encrypted parts are generated. Default is false.
	CleanupPlainZip bool
}

// BatchResult contains information about the built batch.
type BatchResult struct {
	// ZipPath is the path to the plain ZIP file containing all invoices.
	ZipPath string

	// ZipSize is the size of the plain ZIP in bytes.
	ZipSize int64

	// Parts is a list of encrypted parts (for fileParts in KSeF request).
	Parts []BatchPartInfo

	// InvoiceHashes maps original invoice XML documents to their SHA-256 hashes.
	InvoiceHashes []InvoiceHash

	// AESKey is the single AES-256 key used to encrypt all parts of this ZIP.
	// IV jest per-part, ale klucz jest wspólny dla całej paczki.
	AESKey []byte
}

// BatchPartInfo describes one encrypted part of the ZIP file.
type BatchPartInfo struct {
	// Index is the zero-based index of the part (0,1,2,...).
	Index int

	// PlainOffset is the byte offset in the plain ZIP where this part starts.
	PlainOffset int64

	// PlainSize is the size of this part in the plain ZIP (<= MaxPartSize).
	PlainSize int64

	// CipherPath is the path to the encrypted file containing this part.
	CipherPath string

	// CipherSize is the size of encrypted data (after AES).
	CipherSize int64

	// IV is the initialization vector used for this part (16 bytes).
	// Klucz AES jest wspólny dla całej paczki (BatchResult.AESKey).
	IV []byte
}

// InvoiceHash binds an invoice XML document to its SHA-256 hash computed on
// the original XML bytes (before encryption).
type InvoiceHash struct {
	// ID is a logical identifier of the invoice (path, DB id, etc.).
	ID string

	// FileName is the file name used inside the ZIP.
	FileName string

	// SHA256 is the raw SHA-256 hash of the original XML (32 bytes).
	SHA256 []byte
}

// InvoiceItem represents a single invoice to be added to the ZIP.
type InvoiceItem struct {
	// ID is a logical identifier (np. ścieżka, ID z bazy, itp.).
	ID string

	// FileName is the name of this invoice inside the ZIP.
	// Jeśli puste, builder sam coś wygeneruje.
	FileName string

	// XML is the raw XML content of the invoice.
	XML []byte

	// SHA256 is an optional precomputed SHA-256 hash of XML.
	// Jeśli puste/nil, BuildBatchFromSource policzy SHA samodzielnie.
	SHA256 []byte
}

// InvoiceSource is a generic source of invoices (iterator).
type InvoiceSource interface {
	Next() (*InvoiceItem, error)
}

// fileInvoiceSource implements InvoiceSource for a slice of file paths.
type fileInvoiceSource struct {
	paths []string
	idx   int
}

func NewFileInvoiceSource(paths []string) InvoiceSource {
	return &fileInvoiceSource{
		paths: paths,
	}
}

func (s *fileInvoiceSource) Next() (*InvoiceItem, error) {
	if s.idx >= len(s.paths) {
		return nil, io.EOF
	}
	path := s.paths[s.idx]
	s.idx++

	xmlBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read invoice %q: %w", path, err)
	}

	baseName := filepath.Base(path)
	if baseName == "" || baseName == "." {
		baseName = fmt.Sprintf("invoice_%06d.xml", s.idx)
	}

	return &InvoiceItem{
		ID:       path,
		FileName: baseName,
		XML:      xmlBytes,
	}, nil
}

// buildBatchFromZip takes an existing ZIP file and a list of InvoiceHashes,
// then splits the ZIP into <=MaxPartSize parts, encrypts each part with a
// single AES-256 key (different IV per part), and returns BatchResult.
func buildBatchFromZip(cfg BatchConfig, zipPath string, invoiceHashes []InvoiceHash) (*BatchResult, error) {
	zipFile, err := os.Open(zipPath)
	if err != nil {
		return nil, fmt.Errorf("open zip for splitting: %w", err)
	}
	defer func() { _ = zipFile.Close() }()

	info, err := zipFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat zip file: %w", err)
	}
	totalSize := info.Size()

	if cfg.MaxPartSize <= 0 {
		cfg.MaxPartSize = 100 * 1024 * 1024
	}

	key, keyErr := aes.GenerateRandom256BitsKey()
	if keyErr != nil {
		return nil, fmt.Errorf("generate AES key for batch: %w", keyErr)
	}

	var parts []BatchPartInfo
	var offset int64
	index := 0

	for offset < totalSize {
		remaining := totalSize - offset
		partSize := remaining
		if partSize > cfg.MaxPartSize {
			partSize = cfg.MaxPartSize
		}

		plainPart := make([]byte, partSize)
		n, readErr := zipFile.ReadAt(plainPart, offset)
		if readErr != nil && readErr != io.EOF {
			return nil, fmt.Errorf("read zip part at offset %d: %w", offset, readErr)
		}
		if int64(n) != partSize {
			return nil, fmt.Errorf("short read: expected %d, got %d", partSize, n)
		}

		iv, ivErr := aes.GenerateRandom16BytesIv()
		if ivErr != nil {
			return nil, fmt.Errorf("generate IV for part %d: %w", index, ivErr)
		}

		cipherPart, encErr := aes.EncryptBytesWithAES256CBCPKCS7(plainPart, key, iv)
		if encErr != nil {
			return nil, fmt.Errorf("encrypt part %d: %w", index, encErr)
		}

		partPath := fmt.Sprintf("%s.part-%03d.enc", zipPath, index)
		if writeErr := os.WriteFile(partPath, cipherPart, 0o600); writeErr != nil {
			return nil, fmt.Errorf("write encrypted part %d to %q: %w", index, partPath, writeErr)
		}

		parts = append(parts, BatchPartInfo{
			Index:       index,
			PlainOffset: offset,
			PlainSize:   partSize,
			CipherPath:  partPath,
			CipherSize:  int64(len(cipherPart)),
			IV:          iv,
		})

		offset += partSize
		index++
	}

	if cfg.CleanupPlainZip {
		if rmErr := os.Remove(zipPath); rmErr != nil {
			return &BatchResult{
				ZipPath:       zipPath,
				ZipSize:       totalSize,
				Parts:         parts,
				InvoiceHashes: invoiceHashes,
				AESKey:        key,
			}, fmt.Errorf("batch built, but failed to remove plain zip: %w", rmErr)
		}
	}

	return &BatchResult{
		ZipPath:       zipPath,
		ZipSize:       totalSize,
		Parts:         parts,
		InvoiceHashes: invoiceHashes,
		AESKey:        key,
	}, nil
}
