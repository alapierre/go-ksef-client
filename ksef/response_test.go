package ksef

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/alapierre/go-ksef-client/ksef/api"
)

const facadeTestRef = "20250625-SO-2C3E6C8000-B675CF5D68-07"
const facadePollSuccess = `{"startDate":"2026-07-01T00:00:00Z","authenticationMethod":"Token","authenticationMethodInfo":{"category":"Token","code":"Token","displayName":"Token KSeF"},"status":{"code":200,"description":"success"}}`

type facadeOperation struct {
	name              string
	status            int
	contentType, body string
	legacy            func(*Client, *AuthFacade) (any, error)
	metadata          func(*Client, *AuthFacade) (any, ResponseMetadata, error)
}

func facadeOperations(ctx context.Context) []facadeOperation {
	ctx = Context(ctx, "1111111111")
	key, iv := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 16)
	form := api.FormCode{SystemCode: "FA (3)", SchemaVersion: "1-0E", Value: "FA"}
	batch := api.BatchFileInfo{FileSize: 16, FileHash: bytes.Repeat([]byte{4}, 32), FileParts: []api.BatchFilePartInfo{{OrdinalNumber: 1, FileSize: 16, FileHash: bytes.Repeat([]byte{4}, 32)}}}
	filters := api.InvoiceQueryFilters{SubjectType: api.InvoiceQuerySubjectTypeSubject1, DateRange: api.InvoiceQueryDateRange{DateType: api.InvoiceQueryDateTypeIssue, From: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)}}
	collectiveFilters := api.CollectiveIdentifiersQueryPostReq{DateCreatedFrom: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), DateCreatedTo: time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC)}
	invoices := []api.CollectiveIdentifierInvoice{{KsefNumber: api.KsefNumber(collectiveTestInvoice)}, {KsefNumber: api.KsefNumber(collectiveTestInvoice2)}}
	authInit := &api.AuthenticationInitResponse{ReferenceNumber: api.ReferenceNumber(facadeTestRef), AuthenticationToken: api.AuthenticationInitResponseAuthenticationToken{Token: "auth-token"}}
	return []facadeOperation{
		{name: "OpenInteractiveSession", status: 201, contentType: "application/json", body: `{"referenceNumber":"` + facadeTestRef + `","validUntil":"2026-07-01T12:00:00Z"}`,
			legacy: func(c *Client, a *AuthFacade) (any, error) { return c.OpenInteractiveSession(ctx, form, key, iv) },
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				return c.OpenInteractiveSessionWithMetadata(ctx, form, key, iv)
			},
		},
		{name: "OpenBatchSession", status: 201, contentType: "application/json", body: `{"referenceNumber":"` + facadeTestRef + `","partUploadRequests":[]}`,
			legacy: func(c *Client, a *AuthFacade) (any, error) {
				return c.OpenBatchSession(ctx, form, key, iv, api.OptBool{}, batch)
			},
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				return c.OpenBatchSessionWithMetadata(ctx, form, key, iv, api.OptBool{}, batch)
			},
		},
		{name: "SendInvoice", status: 202, contentType: "application/json", body: `{"referenceNumber":"` + facadeTestRef + `"}`,
			legacy: func(c *Client, a *AuthFacade) (any, error) {
				return c.SendInvoice(ctx, facadeTestRef, api.OptBool{}, []byte("<invoice/>"), key, iv)
			},
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				return c.SendInvoiceWithMetadata(ctx, facadeTestRef, api.OptBool{}, []byte("<invoice/>"), key, iv)
			},
		},
		{name: "CloseInteractiveSession", status: 204, contentType: "application/json", body: ``,
			legacy: func(c *Client, a *AuthFacade) (any, error) { return c.CloseInteractiveSession(ctx, facadeTestRef) },
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				return c.CloseInteractiveSessionWithMetadata(ctx, facadeTestRef)
			},
		},
		{name: "CloseBatchSession", status: 204, contentType: "application/json", body: ``,
			legacy: func(c *Client, a *AuthFacade) (any, error) { return c.CloseBatchSession(ctx, facadeTestRef) },
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				return c.CloseBatchSessionWithMetadata(ctx, facadeTestRef)
			},
		},
		{name: "SessionInvoices", status: 200, contentType: "application/json", body: `{"invoices":[]}`,
			legacy: func(c *Client, a *AuthFacade) (any, error) {
				return c.SessionInvoices(ctx, facadeTestRef, api.OptString{}, api.OptInt32{})
			},
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				return c.SessionInvoicesWithMetadata(ctx, facadeTestRef, api.OptString{}, api.OptInt32{})
			},
		},
		{name: "QueryInvoicesMetadata", status: 200, contentType: "application/json", body: `{"hasMore":false,"isTruncated":false,"invoices":[]}`,
			legacy: func(c *Client, a *AuthFacade) (any, error) {
				return c.QueryInvoicesMetadata(ctx, filters, api.InvoicesQueryMetadataPostParams{})
			},
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				return c.QueryInvoicesMetadataWithMetadata(ctx, filters, api.InvoicesQueryMetadataPostParams{})
			},
		},
		{name: "GetInvoiceByKsefNumber", status: 200, contentType: "application/xml", body: `<invoice/>`,
			legacy: func(c *Client, a *AuthFacade) (any, error) {
				return c.GetInvoiceByKsefNumber(ctx, collectiveTestInvoice)
			},
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				return c.GetInvoiceByKsefNumberWithMetadata(ctx, collectiveTestInvoice)
			},
		},
		{name: "GetUPO", status: 200, contentType: "application/xml", body: `<upo/>`,
			legacy: func(c *Client, a *AuthFacade) (any, error) { return c.GetUPO(ctx, facadeTestRef, facadeTestRef) },
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				return c.GetUPOWithMetadata(ctx, facadeTestRef, facadeTestRef)
			},
		},
		{name: "StartInvoiceExport", status: 201, contentType: "application/json", body: `{"referenceNumber":"` + facadeTestRef + `"}`,
			legacy: func(c *Client, a *AuthFacade) (any, error) {
				return c.StartInvoiceExport(ctx, filters, api.OptBool{}, key, iv)
			},
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				return c.StartInvoiceExportWithMetadata(ctx, filters, api.OptBool{}, key, iv)
			},
		},
		{name: "StartInvoiceExportWithGeneratedKey", status: 201, contentType: "application/json", body: `{"referenceNumber":"` + facadeTestRef + `"}`,
			legacy: func(c *Client, a *AuthFacade) (any, error) {
				return c.StartInvoiceExportWithGeneratedKey(ctx, filters, api.OptBool{})
			},
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				return c.StartInvoiceExportWithGeneratedKeyWithMetadata(ctx, filters, api.OptBool{})
			},
		},
		{name: "InvoiceExportStatus", status: 200, contentType: "application/json", body: `{"status":{"code":100,"description":"in progress"}}`,
			legacy: func(c *Client, a *AuthFacade) (any, error) { return c.InvoiceExportStatus(ctx, facadeTestRef) },
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				return c.InvoiceExportStatusWithMetadata(ctx, facadeTestRef)
			},
		},
		{name: "GenerateCollectiveIdentifier", status: 201, contentType: "application/json", body: `{"collectiveIdentifierNumber":"` + collectiveTestNumber + `"}`,
			legacy: func(c *Client, a *AuthFacade) (any, error) { return c.GenerateCollectiveIdentifier(ctx, invoices) },
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				return c.GenerateCollectiveIdentifierWithMetadata(ctx, invoices)
			},
		},
		{name: "GetCollectiveIdentifierInvoices", status: 200, contentType: "application/json", body: `{"invoices":[]}`,
			legacy: func(c *Client, a *AuthFacade) (any, error) {
				return c.GetCollectiveIdentifierInvoices(ctx, []string{collectiveTestNumber}, api.OptString{}, api.OptInt32{})
			},
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				return c.GetCollectiveIdentifierInvoicesWithMetadata(ctx, []string{collectiveTestNumber}, api.OptString{}, api.OptInt32{})
			},
		},
		{name: "GetCollectiveIdentifiersByKsefNumber", status: 200, contentType: "application/json", body: `{"collectiveIdentifiers":[]}`,
			legacy: func(c *Client, a *AuthFacade) (any, error) {
				return c.GetCollectiveIdentifiersByKsefNumber(ctx, collectiveTestInvoice, api.OptString{}, api.OptInt32{})
			},
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				return c.GetCollectiveIdentifiersByKsefNumberWithMetadata(ctx, collectiveTestInvoice, api.OptString{}, api.OptInt32{})
			},
		},
		{name: "QueryCollectiveIdentifiers", status: 200, contentType: "application/json", body: `{"collectiveIdentifiers":[]}`,
			legacy: func(c *Client, a *AuthFacade) (any, error) {
				return c.QueryCollectiveIdentifiers(ctx, collectiveFilters, api.OptString{}, api.OptInt32{})
			},
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				return c.QueryCollectiveIdentifiersWithMetadata(ctx, collectiveFilters, api.OptString{}, api.OptInt32{})
			},
		},
		{name: "GetChallenge", status: 200, contentType: "application/json", body: `{"challenge":"20250514-CR-226FB7B000-3ACF9BE4C0-10","timestamp":"2026-07-01T12:00:00Z","timestampMs":1782907200000,"clientIp":"127.0.0.1"}`,
			legacy:   func(c *Client, a *AuthFacade) (any, error) { return a.GetChallenge(ctx) },
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) { return a.GetChallengeWithMetadata(ctx) },
		},
		{name: "AuthWithToken", status: 202, contentType: "application/json", body: `{"referenceNumber":"` + facadeTestRef + `","authenticationToken":{"token":"auth-token","validUntil":"2026-07-01T12:00:00Z"}}`,
			legacy: func(c *Client, a *AuthFacade) (any, error) {
				return a.AuthWithToken(ctx, api.Challenge("20250514-CR-226FB7B000-3ACF9BE4C0-10"), []byte("encrypted"))
			},
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				return a.AuthWithTokenWithMetadata(ctx, api.Challenge("20250514-CR-226FB7B000-3ACF9BE4C0-10"), []byte("encrypted"))
			},
		},
		{name: "AuthWithXades", status: 202, contentType: "application/json", body: `{"referenceNumber":"` + facadeTestRef + `","authenticationToken":{"token":"auth-token","validUntil":"2026-07-01T12:00:00Z"}}`,
			legacy: func(c *Client, a *AuthFacade) (any, error) { return a.AuthWithXades(ctx, []byte("<signed/>")) },
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				return a.AuthWithXadesWithMetadata(ctx, []byte("<signed/>"))
			},
		},
		{name: "RefreshToken", status: 200, contentType: "application/json", body: `{"accessToken":{"token":"access-token","validUntil":"2026-07-01T12:00:00Z"}}`,
			legacy: func(c *Client, a *AuthFacade) (any, error) { return a.RefreshToken(ctx, "refresh-token") },
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				return a.RefreshTokenWithMetadata(ctx, "refresh-token")
			},
		},
		{name: "CloseAuthSession", status: 204, contentType: "application/json", body: ``,
			legacy: func(c *Client, a *AuthFacade) (any, error) { return nil, a.CloseAuthSession(ctx, "access-token") },
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				metadata, err := a.CloseAuthSessionWithMetadata(ctx, "access-token")
				return nil, metadata, err
			},
		},
		{name: "AuthWaitAndRedeem", status: 200, contentType: "application/json", body: `{"accessToken":{"token":"access","validUntil":"2026-07-01T12:00:00Z"},"refreshToken":{"token":"refresh","validUntil":"2026-07-02T12:00:00Z"}}`,
			legacy: func(c *Client, a *AuthFacade) (any, error) {
				return a.AuthWaitAndRedeem(ctx, authInit, time.Nanosecond)
			},
			metadata: func(c *Client, a *AuthFacade) (any, ResponseMetadata, error) {
				return a.AuthWaitAndRedeemWithMetadata(ctx, authInit, time.Nanosecond)
			},
		},
	}
}

func facadeTestEncryptor(t *testing.T) *EncryptionService {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	enc := &EncryptionService{}
	WithPreloadedKeys(PreloadedKeys{SymmetricRSAPub: &key.PublicKey, SymmetricValidTo: time.Now().Add(time.Hour)})(enc)
	return enc
}

func TestFacadeResponseErrors(t *testing.T) {
	enc := facadeTestEncryptor(t)
	type errorCase struct {
		name                       string
		status                     int
		contentType, body, message string
		details                    []ErrorDetail
		retry                      string
		marker                     error
	}
	cases := []errorCase{
		{name: "exception", status: 400, contentType: "application/json", body: `{"exception":{"exceptionDetailList":[{"exceptionCode":21405,"exceptionDescription":"Validation failed","details":["first","second"]},{"exceptionCode":21406,"details":["fallback"]}]}}`, message: "Validation failed", details: []ErrorDetail{{Code: 21405, Message: "Validation failed", Details: []string{"first", "second"}}, {Code: 21406, Message: "fallback", Details: []string{"fallback"}}}},
		{name: "problem", status: 400, contentType: "application/problem+json", body: `{"title":"Bad Request","status":400,"detail":"Invalid input","instance":"/request/1","errors":[{"code":21405,"description":"Validation failed","details":["first","second"]},{"code":21406,"description":"Another error","details":null}],"timestamp":"2026-07-01T00:00:00Z","traceId":"trace-1"}`, message: "Invalid input", details: []ErrorDetail{{Code: 21405, Message: "Validation failed", Details: []string{"first", "second"}}, {Code: 21406, Message: "Another error"}}},
		{name: "unauthorized", status: 401, contentType: "application/problem+json", body: `{"title":"Unauthorized","status":401,"detail":"Expired token","timestamp":"2026-07-01T00:00:00Z"}`, message: "Expired token", marker: ErrUnauthorized},
		{name: "forbidden", status: 403, contentType: "application/problem+json", body: `{"title":"Forbidden","status":403,"detail":"Denied","reasonCode":"missing-permissions","security":{"requiredAnyOfPermissions":["InvoiceRead"]}}`, message: "Denied", marker: ErrForbidden},
		{name: "gone", status: 410, contentType: "application/problem+json", body: `{"title":"Gone","status":410,"detail":"Expired","instance":"/request/1","timestamp":"2026-07-01T00:00:00Z","traceId":"trace-1"}`, message: "Expired"},
	}
	for _, retry := range []string{"", "0", "17"} {
		cases = append(cases,
			errorCase{
				name: "rate_json_" + retry, status: 429, contentType: "application/json", body: `{"status":{"code":429,"description":"Too Many Requests","details":["Limit exceeded","Try later"]}}`, message: "Too Many Requests", details: []ErrorDetail{{Code: 429, Message: "Too Many Requests", Details: []string{"Limit exceeded", "Try later"}}}, retry: retry,
			},
			errorCase{
				name: "rate_problem_" + retry, status: 429, contentType: "application/problem+json", body: `{"title":"Too Many Requests","status":429,"detail":"Limit exceeded","instance":"/request/1","timestamp":"2026-07-01T00:00:00Z","traceId":"trace-1"}`, message: "Limit exceeded", retry: retry,
			},
		)
	}
	for _, op := range facadeOperations(context.Background()) {
		t.Run(op.name, func(t *testing.T) {
			for _, tc := range cases {
				if (tc.status == 401 || tc.status == 403) && (op.name == "GetChallenge" || op.name == "AuthWithToken" || op.name == "AuthWithXades") {
					continue
				}
				if tc.status == 410 && op.name != "InvoiceExportStatus" && op.name != "AuthWaitAndRedeem" {
					continue
				}
				for _, legacy := range []bool{true, false} {
					t.Run(fmt.Sprintf("%s/legacy=%t", tc.name, legacy), func(t *testing.T) {
						calls := 0
						c := newTestClient(t, func(*http.Request) (*http.Response, error) {
							calls++
							response := testJSONResponse(tc.status, tc.contentType, tc.body)
							if tc.retry != "" {
								response.Header.Set("Retry-After", tc.retry)
							}
							return response, nil
						})
						c.encryptor = enc
						a := &AuthFacade{raw: c.raw, httpClient: c.httpClient, env: Test}
						var err error
						if legacy {
							_, err = op.legacy(c, a)
						} else {
							var metadata ResponseMetadata
							_, metadata, err = op.metadata(c, a)
							if metadata != (ResponseMetadata{}) {
								t.Fatalf("metadata on error: %#v", metadata)
							}
						}
						var apiErr *ApiError
						wrapped := fmt.Errorf("caller: %w", err)
						if !errors.As(wrapped, &apiErr) {
							t.Fatalf("expected ApiError, got %T: %v", err, err)
						}
						if apiErr.Status != tc.status || apiErr.Message != tc.message || !reflect.DeepEqual(apiErr.Details, tc.details) {
							t.Fatalf("error = %#v", apiErr)
						}
						assertJSONEqual(t, tc.body, apiErr.Body)
						retry, present := apiErr.RetryAfter.Get()
						wantRetry, _ := strconv.Atoi(tc.retry)
						if present != (tc.retry != "") || int(retry) != wantRetry {
							t.Fatalf("RetryAfter = %d, %t", retry, present)
						}
						if tc.marker != nil && !errors.Is(wrapped, tc.marker) {
							t.Fatalf("missing sentinel %v", tc.marker)
						}
						if tc.status == 410 && errors.Is(wrapped, ErrInvoiceExportExpired) != (op.name == "InvoiceExportStatus") {
							t.Fatalf("incorrect export expired marker: %v", err)
						}
						if calls != 1 {
							t.Fatalf("requests = %d; errors must not be retried", calls)
						}
					})
				}
			}
		})
	}
}

func TestFacadeSuccessfulMetadataAndLegacyAPI(t *testing.T) {
	enc := facadeTestEncryptor(t)
	for _, op := range facadeOperations(context.Background()) {
		for _, warning := range []struct {
			name, value string
			present     bool
		}{{name: "absent"}, {name: "present", value: "maintenance scheduled", present: true}, {name: "empty", present: true}} {
			t.Run(op.name+"/"+warning.name, func(t *testing.T) {
				calls := 0
				c := newTestClient(t, func(r *http.Request) (*http.Response, error) {
					calls++
					if op.name == "AuthWaitAndRedeem" && r.URL.Path == "/v2/auth/"+facadeTestRef {
						response := testJSONResponse(200, "application/json", facadePollSuccess)
						response.Header.Set("X-System-Warning", "poll warning")
						return response, nil
					}
					response := testJSONResponse(op.status, op.contentType, op.body)
					response.Header.Set("x-ms-meta-hash", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 32)))
					if warning.present {
						response.Header.Set("X-System-Warning", warning.value)
					}
					return response, nil
				})
				c.encryptor = enc
				a := &AuthFacade{raw: c.raw, httpClient: c.httpClient, env: Test}
				result, metadata, err := op.metadata(c, a)
				if err != nil {
					t.Fatal(err)
				}
				value, present := metadata.XSystemWarning.Get()
				if present != warning.present || string(value) != warning.value {
					t.Fatalf("warning = %q, %t", value, present)
				}
				legacy, err := op.legacy(c, a)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(facadeResult(t, result), facadeResult(t, legacy)) {
					t.Fatalf("legacy result differs: %#v / %#v", legacy, result)
				}
				expectedCalls := 2
				if op.name == "AuthWaitAndRedeem" {
					expectedCalls = 4
				}
				if calls != expectedCalls {
					t.Fatalf("requests = %d, want %d", calls, expectedCalls)
				}
			})
		}
	}
}

func facadeResult(t *testing.T, result any) any {
	t.Helper()
	switch v := result.(type) {
	case *InvoiceExport:
		if len(v.Key) != 32 || len(v.IV) != 16 || v.ReferenceNumber != facadeTestRef {
			t.Fatalf("invalid export: %#v", v)
		}
		return v.Response
	case *api.InvoicesKsefKsefNumberGetOKHeaders:
		body, err := io.ReadAll(v.Response.Data)
		if err != nil || string(body) != "<invoice/>" || !bytes.Equal(v.XMsMetaHash, bytes.Repeat([]byte{0xab}, 32)) {
			t.Fatalf("invoice body/hash: %q, %v", body, err)
		}
		return string(body)
	case *api.SessionsReferenceNumberUpoUpoReferenceNumberGetOKHeaders:
		body, err := io.ReadAll(v.Response.Data)
		if err != nil || string(body) != "<upo/>" || !bytes.Equal(v.XMsMetaHash, bytes.Repeat([]byte{0xab}, 32)) {
			t.Fatalf("UPO body/hash: %q, %v", body, err)
		}
		return string(body)
	default:
		return result
	}
}

func TestExceptionStatusIsProvidedByOperation(t *testing.T) {
	exception := &api.ExceptionResponse{}
	if got := HandleAPIError(exception).(*ApiError).Status; got != 0 {
		t.Fatalf("HandleAPIError guessed status %d", got)
	}
	for _, status := range []int{400, 500} {
		if got := responseAPIError(exception, status).(*ApiError).Status; got != status {
			t.Fatalf("status = %d, want %d", got, status)
		}
	}
	// HTTP status comes from the decoded variant, not the untrusted status field.
	err := responseAPIError(&api.TooManyRequestsProblemDetailsHeaders{Response: api.TooManyRequestsProblemDetails{Status: 200, Title: "Too Many Requests"}}, 400).(*ApiError)
	if err.Status != 429 || err.Message != "Too Many Requests" {
		t.Fatalf("error = %#v", err)
	}
}

func TestAuthRedemptionRateLimit(t *testing.T) {
	calls := 0
	c := newTestClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path == "/v2/auth/"+facadeTestRef {
			return testJSONResponse(200, "application/json", facadePollSuccess), nil
		}
		response := testJSONResponse(429, "application/json", `{"status":{"code":429,"description":"Try later","details":[]}}`)
		response.Header.Set("Retry-After", "0")
		return response, nil
	})
	a := &AuthFacade{raw: c.raw, httpClient: c.httpClient, env: Test}
	_, metadata, err := a.AuthWaitAndRedeemWithMetadata(context.Background(), &api.AuthenticationInitResponse{ReferenceNumber: api.ReferenceNumber(facadeTestRef), AuthenticationToken: api.AuthenticationInitResponseAuthenticationToken{Token: "auth-token"}}, time.Nanosecond)
	var apiErr *ApiError
	if !errors.As(err, &apiErr) || apiErr.Status != 429 || !apiErr.RetryAfter.IsSet() || apiErr.RetryAfter.Value != 0 || metadata != (ResponseMetadata{}) || calls != 2 {
		t.Fatalf("metadata=%#v, err=%v, calls=%d", metadata, err, calls)
	}
}

var _ TokenRefresher = (*AuthFacade)(nil)

func TestDownloadHashHeader(t *testing.T) {
	for _, op := range facadeOperations(context.Background()) {
		if op.name != "GetInvoiceByKsefNumber" && op.name != "GetUPO" {
			continue
		}
		for _, tc := range []struct {
			name, hash         string
			present, wantError bool
		}{
			{name: "absent"},
			{name: "valid", hash: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 32)), present: true},
			{name: "empty", present: true, wantError: true},
			{name: "invalid base64", hash: "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", present: true, wantError: true},
			{name: "short", hash: base64.StdEncoding.EncodeToString(make([]byte, 24)), present: true, wantError: true},
			{name: "long", hash: base64.StdEncoding.EncodeToString(make([]byte, 34)), present: true, wantError: true},
		} {
			t.Run(op.name+"/"+tc.name, func(t *testing.T) {
				c := newTestClient(t, func(*http.Request) (*http.Response, error) {
					res := testJSONResponse(op.status, op.contentType, op.body)
					if tc.present {
						res.Header.Set("x-ms-meta-hash", tc.hash)
					}
					return res, nil
				})
				res, _, err := op.metadata(c, nil)
				if tc.wantError {
					if err == nil {
						t.Fatal("invalid hash accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				hash := res.(interface{ GetXMsMetaHash() api.Sha256HashBase64 }).GetXMsMetaHash()
				var want []byte
				if tc.present {
					want = bytes.Repeat([]byte{0xab}, 32)
				}
				if !bytes.Equal(hash, want) {
					t.Fatalf("hash = %x, want %x", hash, want)
				}
			})
		}
	}
}
