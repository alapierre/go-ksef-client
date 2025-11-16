package ksef

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alapierre/go-ksef-client/ksef/api"
	"github.com/alapierre/go-ksef-client/ksef/batch"
	"github.com/alapierre/go-ksef-client/ksef/util"
	"github.com/sirupsen/logrus"
)

// ... existing code ...

func TestClient_Batch(t *testing.T) {

	if _, ok := os.LookupEnv("KSEF_NIP"); !ok {
		t.Skip("KSEF_NIP not set – skipping integration test")
	}
	if _, ok := os.LookupEnv("KSEF_TOKEN"); !ok {
		t.Skip("KSEF_TOKEN not set – skipping integration test")
	}

	if _, ok := os.LookupEnv("KSEF_BUYER_NIP"); !ok {
		t.Skip("KSEF_BUYER_NIP not set – skipping integration test")
	}

	logrus.SetLevel(logrus.DebugLevel)

	nip := util.GetEnvOrFailed("KSEF_NIP")
	token := util.GetEnvOrFailed("KSEF_TOKEN")
	buer := util.GetEnvOrFailed("KSEF_BUYER_NIP")

	httpClient := &http.Client{
		Timeout: 60 * time.Second,
	}

	env := Test

	authFacade, err := NewAuthFacade(env, httpClient)
	if err != nil {
		t.Fatal(err)
	}

	encryptor, err := NewEncryptionService(env, httpClient)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	ctx = Context(ctx, nip)

	provider := NewTokenProvider(authFacade, func(ctx context.Context) (*api.AuthenticationTokensResponse, error) {
		return WithKsefToken(ctx, authFacade, encryptor, token)
	})

	client, err := NewClient(env, httpClient, provider)
	if err != nil {
		t.Fatal(err)
	}

	form := api.FormCode{
		SystemCode:    "FA (3)",
		SchemaVersion: "1-0E",
		Value:         "FA",
	}

	// --- 1. Zbudowanie paczki ZIP z fakturami z szablonu (unikalne faktury) ---

	tmpDir := t.TempDir()
	templatePath := filepath.Join("..", "invoice_fa_3_type.xml")

	const invoiceCount = 20
	const maxPartSize = 256 * 1024 // 256 KiB – wymusi kilka partów, jeśli ZIP urośnie

	src := newTemplateBatchInvoiceSource(templatePath, invoiceCount, nip, buer)

	batchCfg := batch.BatchConfig{
		OutputDir:       tmpDir,
		MaxPartSize:     maxPartSize,
		TempFilePattern: "ksef-batch-*.zip",
		CleanupPlainZip: false,
	}

	batchResult, err := batch.BuildBatchFromSource(batchCfg, src)
	if err != nil {
		t.Fatalf("BuildBatchFromSource failed: %v", err)
	}
	if batchResult == nil {
		t.Fatalf("BuildBatchFromSource returned nil result")
	}
	if len(batchResult.Parts) == 0 {
		t.Fatalf("expected at least 1 part, got 0")
	}

	t.Logf("ZIP path: %s, size: %d, parts: %d, invoices: %d",
		batchResult.ZipPath, batchResult.ZipSize, len(batchResult.Parts), len(batchResult.InvoiceHashes))

	// --- 2. Przygotowanie BatchFileInfo do OpenBatchSession ---
	// Uwaga: Sha256HashBase64 to []byte, a ogen sam zrobi Base64 przy serializacji.
	// Dlatego przekazujemy surowe bajty SHA-256, bez ręcznego kodowania Base64.

	var fileParts []api.BatchFilePartInfo
	for _, p := range batchResult.Parts {
		fileParts = append(fileParts, api.BatchFilePartInfo{
			OrdinalNumber: int32(p.Index + 1), // KSeF: numeracja od 1
			FileSize:      p.CipherSize,
			FileHash:      api.Sha256HashBase64(p.CipherSHA256),
		})
	}

	batchFile := api.BatchFileInfo{
		FileSize:  batchResult.ZipSize,
		FileHash:  api.Sha256HashBase64(batchResult.ZipSHA256),
		FileParts: fileParts,
	}

	// --- 3. Przygotowanie EncryptionInfo na podstawie klucza paczki ---

	encryptedKey, err := encryptor.EncryptSymmetricKey(ctx, batchResult.AESKey)
	if err != nil {
		t.Fatalf("EncryptSymmetricKey failed: %v", err)
	}

	enc := api.EncryptionInfo{
		EncryptedSymmetricKey: encryptedKey,
		InitializationVector:  batchResult.IV,
	}

	offline := api.OptBool{} // jeśli potrzebujesz offlineMode = true, użyj offline.SetTo(true)

	// --- 4. Otwarcie sesji wsadowej ---

	openResp, err := client.OpenBatchSession(ctx, form, enc, offline, batchFile)
	if err != nil {
		t.Fatalf("OpenBatchSession failed: %v", err)
	}
	if openResp == nil {
		t.Fatalf("OpenBatchSession returned nil response")
	}

	ref := string(openResp.ReferenceNumber)
	t.Logf("Opened batch session, reference: %s", ref)

	// --- 5. Wysłanie poszczególnych partów (SendBatchPart) ---

	if len(openResp.PartUploadRequests) != len(batchResult.Parts) {
		t.Fatalf("server expects %d parts, we have %d",
			len(openResp.PartUploadRequests), len(batchResult.Parts))
	}

	for _, partReq := range openResp.PartUploadRequests {
		ord := int(partReq.OrdinalNumber)
		if ord <= 0 || ord > len(batchResult.Parts) {
			t.Fatalf("unexpected ordinalNumber %d in PartUploadRequests", ord)
		}

		part := batchResult.Parts[ord-1]

		data, err := os.ReadFile(part.CipherPath)
		if err != nil {
			t.Fatalf("reading encrypted part %d from %s failed: %v", ord, part.CipherPath, err)
		}

		res, err := client.SendBatchPart(ctx, data, partReq)
		if err != nil {
			t.Fatalf("SendBatchPart failed for part %d: %v (status=%d, body=%s)",
				ord, err, res.StatusCode, string(res.Body))
		}
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("expected HTTP 201 for part %d, got %d: %s",
				ord, res.StatusCode, res.Message)
		}

		t.Logf("part %d uploaded, status=%d", ord, res.StatusCode)
	}

	// --- 6. Zamknięcie sesji wsadowej ---

	closedRef, err := client.CloseBatchSession(ctx, ref)
	if err != nil {
		t.Fatalf("CloseBatchSession failed: %v", err)
	}
	if closedRef != ref {
		t.Fatalf("CloseBatchSession returned different reference: got %s, want %s", closedRef, ref)
	}

	t.Logf("batch session closed: %s", closedRef)
}

// templateBatchInvoiceSource – analogicznie do batch.templateInvoiceSource,
// ale używane w teście integracyjnym klienta, z NIP-ami z env.
type templateBatchInvoiceSource struct {
	templatePath string
	count        int
	idx          int
	sellerNip    string
	buyerNip     string
}

func newTemplateBatchInvoiceSource(templatePath string, count int, sellerNip, buyerNip string) *templateBatchInvoiceSource {
	return &templateBatchInvoiceSource{
		templatePath: templatePath,
		count:        count,
		sellerNip:    sellerNip,
		buyerNip:     buyerNip,
	}
}

func (s *templateBatchInvoiceSource) Next() (*batch.InvoiceItem, error) {
	if s.idx >= s.count {
		return nil, io.EOF
	}

	i := s.idx

	xmlBytes, err := util.ReplacePlaceholdersInXML(s.templatePath, map[string]any{
		"NIP":        s.sellerNip, // NIP sprzedawcy z env
		"ISSUE_DATE": time.Now(),
		"BUYER_NIP":  s.buyerNip, // NIP kupującego z env
	})
	if err != nil {
		return nil, fmt.Errorf("ReplacePlaceholdersInXML failed (i=%d): %w", i, err)
	}

	fileName := fmt.Sprintf("invoice_%04d.xml", i)

	item := batch.NewInvoiceItem(fileName, fileName, xmlBytes)

	s.idx++
	return item, nil
}
