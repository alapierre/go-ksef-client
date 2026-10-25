package ksef

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/alapierre/go-ksef-client/ksef/api"
)

func TestClientUnwrapsGeneratedResponses(t *testing.T) {
	const ref = "20250625-SO-2C3E6C8000-B675CF5D68-07"
	ctx := context.Background()
	form := api.FormCode{SystemCode: "FA (3)", SchemaVersion: "1-0E", Value: "FA"}
	enc := api.EncryptionInfo{EncryptedSymmetricKey: bytes.Repeat([]byte{1}, 256), InitializationVector: bytes.Repeat([]byte{2}, 16), PublicKeyId: api.NewOptNilByte(bytes.Repeat([]byte{3}, 32))}
	filters := api.InvoiceQueryFilters{SubjectType: api.InvoiceQuerySubjectTypeSubject1, DateRange: api.InvoiceQueryDateRange{DateType: api.InvoiceQueryDateTypeIssue, From: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)}}
	cases := []struct {
		name, path, body string
		status           int
		call             func(*Client) (any, error)
	}{
		{"online", "/sessions/online", `{"referenceNumber":"` + ref + `","validUntil":"2026-07-01T12:00:00Z"}`, 201, func(c *Client) (any, error) { return c.openInteractiveSession(ctx, form, enc) }},
		{"batch", "/sessions/batch", `{"referenceNumber":"` + ref + `","partUploadRequests":[]}`, 201, func(c *Client) (any, error) {
			return c.openBatchSession(ctx, form, enc, api.OptBool{}, api.BatchFileInfo{FileSize: 16, FileHash: bytes.Repeat([]byte{4}, 32), FileParts: []api.BatchFilePartInfo{{OrdinalNumber: 1, FileSize: 16, FileHash: bytes.Repeat([]byte{4}, 32)}}})
		}},
		{"send_invoice", "/sessions/online/" + ref + "/invoices", `{"referenceNumber":"` + ref + `"}`, 202, func(c *Client) (any, error) {
			result, err := c.SendInvoice(ctx, ref, api.OptBool{}, []byte("<invoice/>"), bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 16))
			if err == nil && result != ref {
				t.Errorf("reference = %q", result)
			}
			return &api.SendInvoiceResponse{ReferenceNumber: api.ReferenceNumber(result)}, err
		}},
		{"session_invoices", "/sessions/" + ref + "/invoices", `{"invoices":[]}`, 200, func(c *Client) (any, error) { return c.SessionInvoices(ctx, ref, api.OptString{}, api.OptInt32{}) }},
		{"metadata", "/invoices/query/metadata", `{"hasMore":false,"isTruncated":false,"invoices":[]}`, 200, func(c *Client) (any, error) {
			return c.QueryInvoicesMetadata(ctx, filters, api.InvoicesQueryMetadataPostParams{})
		}},
		{"export", "/invoices/exports", `{"referenceNumber":"` + ref + `"}`, 201, func(c *Client) (any, error) {
			result, err := c.startInvoiceExport(ctx, filters, api.OptBool{}, enc, []byte("key"), []byte("iv"))
			if err != nil {
				return nil, err
			}
			if result.ReferenceNumber != ref || string(result.Key) != "key" || string(result.IV) != "iv" {
				t.Errorf("export = %#v", result)
			}
			return result.Response, nil
		}},
		{"export_status", "/invoices/exports/" + ref, `{"status":{"code":100,"description":"in progress"}}`, 200, func(c *Client) (any, error) { return c.InvoiceExportStatus(ctx, ref) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := newTestClient(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Path != "/v2"+tc.path {
					t.Fatalf("path = %s", r.URL.Path)
				}
				if tc.name == "online" || tc.name == "batch" || tc.name == "export" {
					var request struct {
						Encryption struct {
							PublicKeyID string `json:"publicKeyId"`
						} `json:"encryption"`
					}
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Fatal(err)
					}
					if request.Encryption.PublicKeyID != base64.StdEncoding.EncodeToString(enc.PublicKeyId.Value) {
						t.Fatal("incorrect publicKeyId encoding")
					}
				}
				return testJSONResponse(tc.status, "application/json", tc.body), nil
			})
			response, err := tc.call(c)
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			assertJSONEqual(t, tc.body, body)
			if calls != 1 {
				t.Fatalf("requests = %d", calls)
			}
		})
	}
}

func TestAuthGeneratedResponses(t *testing.T) {
	const ref = "20250514-AU-2DFC46C000-3AC6D5877F-D4"
	const challenge = "20250514-CR-226FB7B000-3ACF9BE4C0-10"
	ctx := Context(context.Background(), "1111111111")
	authBody := `{"referenceNumber":"` + ref + `","authenticationToken":{"token":"auth-token","validUntil":"2026-07-01T12:00:00Z"}}`
	cases := []struct {
		name, path, body string
		status           int
		call             func(*AuthFacade) (any, error)
	}{
		{"challenge", "/auth/challenge", `{"challenge":"` + challenge + `","timestamp":"2026-07-01T12:00:00Z","timestampMs":1782907200000,"clientIp":"127.0.0.1"}`, 200, func(a *AuthFacade) (any, error) { return a.GetChallenge(ctx) }},
		{"token", "/auth/ksef-token", authBody, 202, func(a *AuthFacade) (any, error) {
			return a.AuthWithToken(ctx, api.Challenge(challenge), []byte("encrypted"), bytes.Repeat([]byte{1}, 32))
		}},
		{"xades", "/auth/xades-signature", authBody, 202, func(a *AuthFacade) (any, error) { return a.AuthWithXades(ctx, []byte("<signed/>")) }},
		{"refresh", "/auth/token/refresh", `{"accessToken":{"token":"access-token","validUntil":"2026-07-01T12:00:00Z"}}`, 200, func(a *AuthFacade) (any, error) {
			token, err := a.RefreshToken(ctx, "refresh-token")
			return &api.AuthenticationTokenRefreshResponse{AccessToken: api.AuthenticationTokenRefreshResponseAccessToken(token)}, err
		}},
		{"redeem", "/auth/token/redeem", `{"accessToken":{"token":"access-token","validUntil":"2026-07-01T12:00:00Z"},"refreshToken":{"token":"refresh-token","validUntil":"2026-07-02T12:00:00Z"}}`, 200, func(a *AuthFacade) (any, error) { return redeemTokens(ctx, a.raw) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/v2"+tc.path {
					t.Fatalf("path = %s", r.URL.Path)
				}
				if tc.name == "refresh" && r.Header.Get("Authorization") != "Bearer refresh-token" {
					t.Fatal("wrong refresh token")
				}
				return testJSONResponse(tc.status, "application/json", tc.body), nil
			})
			a := &AuthFacade{raw: c.raw, httpClient: c.httpClient, env: Test}
			response, err := tc.call(a)
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			assertJSONEqual(t, tc.body, body)
		})
	}
}

func TestExportFiltersPreserveJSON(t *testing.T) {
	const base = `"subjectType":"Subject1","dateRange":{"dateType":"Issue","from":"2026-07-01T00:00:00Z","to":"2026-07-02T00:00:00Z","restrictToPermanentStorageHwmDate":false}`
	for _, extra := range []string{
		"",
		`,"amount":null,"buyerIdentifier":null`,
		`,"amount":{"type":"Gross","from":0,"to":500},"buyerIdentifier":{"type":"Nip","value":"1111111111"},"ksefNumber":"` + collectiveTestInvoice + `","invoiceNumber":"FV/1","sellerNip":"1111111111","currencyCodes":["PLN"],"invoicingMode":"Online","isSelfInvoicing":false,"formType":"FA","invoiceTypes":["Vat"],"hasAttachment":false`,
	} {
		input := "{" + base + extra + "}"
		var filters api.InvoiceQueryFilters
		if err := json.Unmarshal([]byte(input), &filters); err != nil {
			t.Fatal(err)
		}
		converted := exportQueryFilters(filters)
		encoded, err := json.Marshal(&converted)
		if err != nil {
			t.Fatal(err)
		}
		assertJSONEqual(t, input, encoded)
	}
}

func TestAuthWaitAndRedeemGeneratedStatus(t *testing.T) {
	const ref = "20250514-AU-2DFC46C000-3AC6D5877F-D4"
	var paths []string
	c := newTestClient(t, func(r *http.Request) (*http.Response, error) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer auth-token" {
			t.Fatal("wrong auth token")
		}
		switch r.URL.Path {
		case "/v2/auth/" + ref:
			return testJSONResponse(200, "application/json", `{"startDate":"2026-07-01T00:00:00Z","authenticationMethod":"Token","authenticationMethodInfo":{"category":"Token","code":"Token","displayName":"Token KSeF"},"status":{"code":200,"description":"success"}}`), nil
		case "/v2/auth/token/redeem":
			return testJSONResponse(200, "application/json", `{"accessToken":{"token":"access","validUntil":"2026-07-01T12:00:00Z"},"refreshToken":{"token":"refresh","validUntil":"2026-07-02T12:00:00Z"}}`), nil
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
			return nil, io.EOF
		}
	})
	a := &AuthFacade{raw: c.raw, httpClient: c.httpClient, env: Test}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := a.AuthWaitAndRedeem(ctx, &api.AuthenticationInitResponse{ReferenceNumber: api.ReferenceNumber(ref), AuthenticationToken: api.AuthenticationInitResponseAuthenticationToken{Token: "auth-token"}}, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if result.AccessToken.Token != "access" || result.RefreshToken.Token != "refresh" || len(paths) != 2 {
		t.Fatalf("result = %#v, paths = %v", result, paths)
	}
}
