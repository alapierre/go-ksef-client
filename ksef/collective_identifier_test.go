package ksef

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alapierre/go-ksef-client/ksef/api"
)

const (
	collectiveTestNumber   = "1111111111-IZ202607-65ED02180000-E7"
	collectiveTestInvoice  = "1111111111-20260101-111111111111-11"
	collectiveTestInvoice2 = "1111111111-20260101-222222222222-22"
)

type testRoundTripper func(*http.Request) (*http.Response, error)

func (f testRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newTestClient(t *testing.T, transport testRoundTripper) *Client {
	t.Helper()
	httpClient := &http.Client{Transport: transport}
	raw, err := api.NewClient("https://ksef.example/v2", localStaticBearer{Token: "test-token"}, api.WithClient(httpClient))
	if err != nil {
		t.Fatal(err)
	}
	return &Client{raw: raw, httpClient: httpClient}
}

func testJSONResponse(status int, contentType, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {contentType}}, Body: io.NopCloser(strings.NewReader(body))}
}

func assertJSONEqual(t *testing.T, want string, got []byte) {
	t.Helper()
	var expected, actual any
	if err := json.Unmarshal([]byte(want), &expected); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got, &actual); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("JSON = %s, want %s", got, want)
	}
}

type collectiveOperationTest struct {
	name, method, path, request, response string
	status                                int
	call                                  func(*Client, context.Context, api.OptString, api.OptInt32) (any, error)
}

func collectiveOperations() []collectiveOperationTest {
	return []collectiveOperationTest{
		{
			name: "generate", method: http.MethodPost, path: "/collective-identifiers", status: http.StatusCreated,
			request:  `{"invoices":[{"ksefNumber":"` + collectiveTestInvoice + `","payment":{"amount":123.45,"currency":"PLN"},"description":"Faktura 1"},{"ksefNumber":"` + collectiveTestInvoice2 + `"}]}`,
			response: `{"collectiveIdentifierNumber":"` + collectiveTestNumber + `"}`,
			call: func(c *Client, ctx context.Context, _ api.OptString, _ api.OptInt32) (any, error) {
				return c.GenerateCollectiveIdentifier(ctx, []api.CollectiveIdentifierInvoice{
					{KsefNumber: api.KsefNumber(collectiveTestInvoice), Payment: api.NewOptNilCollectiveIdentifierInvoicePayment(api.CollectiveIdentifierInvoicePayment{Amount: 123.45, Currency: api.CurrencyCodePLN}), Description: api.NewOptNilString("Faktura 1")},
					{KsefNumber: api.KsefNumber(collectiveTestInvoice2)},
				})
			},
		},
		{
			name: "invoices", method: http.MethodPost, path: "/collective-identifiers/invoices", status: http.StatusOK,
			request:  `{"collectiveIdentifierNumbers":["` + collectiveTestNumber + `","2222222222-IZ202607-65ED02180000-E8"]}`,
			response: `{"continuationToken":"next-page","invoices":[{"ksefNumber":"` + collectiveTestInvoice + `","collectiveIdentifierNumber":"` + collectiveTestNumber + `","payment":{"amount":123.45,"currency":"PLN"},"description":"Faktura 1","detailsHidden":false},{"ksefNumber":"` + collectiveTestInvoice2 + `","collectiveIdentifierNumber":"2222222222-IZ202607-65ED02180000-E8","payment":null,"description":null,"detailsHidden":true}]}`,
			call: func(c *Client, ctx context.Context, token api.OptString, size api.OptInt32) (any, error) {
				return c.GetCollectiveIdentifierInvoices(ctx, []string{collectiveTestNumber, "2222222222-IZ202607-65ED02180000-E8"}, token, size)
			},
		},
		{
			name: "by_ksef_number", method: http.MethodGet, path: "/collective-identifiers/ksef/" + collectiveTestInvoice, status: http.StatusOK,
			response: `{"continuationToken":null,"collectiveIdentifiers":[{"collectiveIdentifierNumber":"` + collectiveTestNumber + `","dateCreated":"2026-07-01T12:00:00Z","createdInCurrentContext":false}]}`,
			call: func(c *Client, ctx context.Context, token api.OptString, size api.OptInt32) (any, error) {
				return c.GetCollectiveIdentifiersByKsefNumber(ctx, collectiveTestInvoice, token, size)
			},
		},
		{
			name: "query", method: http.MethodPost, path: "/collective-identifiers/query", status: http.StatusOK,
			request:  `{"collectiveIdentifierNumber":"` + collectiveTestNumber + `","dateCreatedFrom":"2026-07-01T00:00:00Z","dateCreatedTo":"2026-07-31T00:00:00Z","invoiceCountFrom":2,"invoiceCountTo":50,"createdInCurrentContext":false}`,
			response: `{"continuationToken":"next-page","collectiveIdentifiers":[{"collectiveIdentifierNumber":"` + collectiveTestNumber + `","dateCreated":"2026-07-01T12:00:00Z","invoiceCount":2,"createdInCurrentContext":false}]}`,
			call: func(c *Client, ctx context.Context, token api.OptString, size api.OptInt32) (any, error) {
				return c.QueryCollectiveIdentifiers(ctx, api.CollectiveIdentifiersQueryPostReq{
					CollectiveIdentifierNumber: api.NewOptNilString(collectiveTestNumber),
					DateCreatedFrom:            time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), DateCreatedTo: time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC),
					InvoiceCountFrom: api.NewOptNilInt32(2), InvoiceCountTo: api.NewOptNilInt32(50), CreatedInCurrentContext: api.NewOptNilBool(false),
				}, token, size)
			},
		},
	}
}

func TestCollectiveIdentifiersRequestsAndResponses(t *testing.T) {
	for _, op := range collectiveOperations() {
		t.Run(op.name, func(t *testing.T) {
			for _, paginated := range []bool{false, true} {
				t.Run(map[bool]string{false: "first_page", true: "continuation"}[paginated], func(t *testing.T) {
					calls := 0
					client := newTestClient(t, func(r *http.Request) (*http.Response, error) {
						calls++
						if r.Method != op.method || r.URL.Path != "/v2"+op.path {
							t.Fatalf("request = %s %s", r.Method, r.URL)
						}
						if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
							t.Fatalf("Authorization = %q", got)
						}
						wantToken, wantSize := "", ""
						if paginated && op.name != "generate" {
							wantToken, wantSize = "current-token", "20"
						}
						if got := r.Header.Get("X-Continuation-Token"); got != wantToken {
							t.Fatalf("continuation token = %q, want %q", got, wantToken)
						}
						if got := r.URL.Query().Get("pageSize"); got != wantSize {
							t.Fatalf("pageSize = %q, want %q", got, wantSize)
						}
						if op.request != "" {
							if r.Header.Get("Content-Type") != "application/json" {
								t.Fatalf("Content-Type = %q", r.Header.Get("Content-Type"))
							}
							body, err := io.ReadAll(r.Body)
							if err != nil {
								t.Fatal(err)
							}
							assertJSONEqual(t, op.request, body)
						} else if r.Body != nil && r.Body != http.NoBody {
							t.Fatal("GET must not have a body")
						}
						return testJSONResponse(op.status, "application/json", op.response), nil
					})
					var token api.OptString
					var size api.OptInt32
					if paginated {
						token.SetTo("current-token")
						size.SetTo(20)
					}
					result, err := op.call(client, context.Background(), token, size)
					if err != nil {
						t.Fatal(err)
					}
					body, err := json.Marshal(result)
					if err != nil {
						t.Fatal(err)
					}
					assertJSONEqual(t, op.response, body)
					if calls != 1 {
						t.Fatalf("requests = %d, want 1", calls)
					}
				})
			}
		})
	}
}

func TestCollectiveIdentifiersErrors(t *testing.T) {
	cases := []struct {
		name              string
		status            int
		contentType, body string
		want              error
		apiCode           int
	}{
		{name: "unauthorized", status: 401, contentType: "application/problem+json", body: `{"title":"Unauthorized","status":401,"detail":"expired","timestamp":"2026-07-01T00:00:00Z"}`, want: ErrUnauthorized},
		{name: "forbidden", status: 403, contentType: "application/problem+json", body: `{"title":"Forbidden","status":403,"detail":"denied","reasonCode":"missing-permissions"}`, want: ErrForbidden},
		{name: "api_error", status: 400, contentType: "application/json", body: `{"exception":{"exceptionDetailList":[{"exceptionCode":71005,"exceptionDescription":"Duplicate invoice","details":["duplicate KSeF number"]}]}}`, apiCode: 71005},
		{name: "malformed_response", status: 200, contentType: "application/json", body: `{`},
		{name: "unexpected_status", status: 500, contentType: "application/json", body: `{}`},
		{name: "rate_limit", status: 429, contentType: "application/json", body: `{"status":{"code":429,"description":"Too many requests"}}`},
	}
	for _, op := range collectiveOperations() {
		t.Run(op.name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					client := newTestClient(t, func(r *http.Request) (*http.Response, error) {
						status := tc.status
						if tc.name == "malformed_response" {
							status = op.status
						}
						return testJSONResponse(status, tc.contentType, tc.body), nil
					})
					result, err := op.call(client, context.Background(), api.OptString{}, api.OptInt32{})
					if err == nil {
						t.Fatal("expected error")
					}
					if !reflect.ValueOf(result).IsNil() {
						t.Fatalf("result on failure = %#v", result)
					}
					if tc.want != nil && !errors.Is(err, tc.want) {
						t.Fatalf("error = %v, want %v", err, tc.want)
					}
					if tc.apiCode != 0 {
						var apiErr *ApiError
						if !errors.As(err, &apiErr) || len(apiErr.Details) != 1 || apiErr.Details[0].Code != tc.apiCode || apiErr.Message != "Duplicate invoice" || !reflect.DeepEqual(apiErr.Details[0].Details, []string{"duplicate KSeF number"}) {
							t.Fatalf("API error = %#v (%v)", apiErr, err)
						}
					}
				})
			}
			t.Run("transport", func(t *testing.T) {
				expected := errors.New("transport failure")
				client := newTestClient(t, func(*http.Request) (*http.Response, error) { return nil, expected })
				_, err := op.call(client, context.Background(), api.OptString{}, api.OptInt32{})
				if !errors.Is(err, expected) {
					t.Fatalf("error = %v", err)
				}
			})
			t.Run("cancellation", func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				client := newTestClient(t, func(r *http.Request) (*http.Response, error) { return nil, r.Context().Err() })
				_, err := op.call(client, ctx, api.OptString{}, api.OptInt32{})
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("error = %v", err)
				}
			})
		})
	}
}

func TestGenerateCollectiveIdentifierValidation(t *testing.T) {
	client := newTestClient(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid request reached transport")
		return nil, nil
	})
	for _, invoices := range [][]api.CollectiveIdentifierInvoice{nil, {}, {{KsefNumber: api.KsefNumber(collectiveTestInvoice)}}} {
		result, err := client.GenerateCollectiveIdentifier(context.Background(), invoices)
		if err == nil || result != nil {
			t.Fatalf("result = %#v, error = %v", result, err)
		}
	}
}
