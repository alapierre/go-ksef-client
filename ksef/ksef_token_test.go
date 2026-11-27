package ksef

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/alapierre/go-ksef-client/ksef/api"
)

const tokenTestReference = "20261106-EC-22ACCDF000-5CDA6D5392-B0"
const tokenTestPrefix = tokenTestReference + "|nip-1111111111|"

func tokenTestRequest() api.TokensRev2PostReq {
	return api.TokensRev2PostReq{
		Permissions: []api.TokenPermissionType{api.TokenPermissionTypeInvoiceRead},
		Description: "Read invoices",
	}
}

func tokenStatusJSON(code, rawCode string) string {
	return fmt.Sprintf(`{
		"referenceNumber":%q,
		"authorIdentifier":{"type":{"code":"Nip","rawCode":"Nip","displayName":"Nip"},"value":"1111111111"},
		"contextIdentifier":{"type":{"code":"Nip","rawCode":"Nip","displayName":"Nip"},"value":"1111111111"},
		"description":"Read invoices","requestedPermissions":[],
		"dateCreated":"2027-01-05T08:00:00Z","validFrom":"2027-01-06T08:00:00Z",
		"validTo":"2027-03-12T14:15:16.1234567+01:00",
		"status":{"code":%q,"rawCode":%q,"displayName":"Status label"}
	}`, tokenTestReference, code, rawCode)
}

func TestParseKsefTokenExpiryDate(t *testing.T) {
	for _, tc := range []struct {
		name, token string
		want        time.Time
	}{
		{"embedded day", tokenTestPrefix + "exp-20270312|secret", time.Date(2027, 3, 12, 0, 0, 0, 0, time.UTC)},
		{"leap day", tokenTestReference + "|internalId-1111111111-12345|exp-20280229|secret", time.Date(2028, 2, 29, 0, 0, 0, 0, time.UTC)},
		{name: "legacy", token: tokenTestPrefix + "secret"},
		{name: "nonexistent day", token: tokenTestPrefix + "exp-20270229|secret"},
		{name: "short date", token: tokenTestPrefix + "exp-2027312|secret"},
		{name: "unknown format", token: tokenTestPrefix + "other-20270312|secret"},
		{name: "expiry in secret position", token: tokenTestPrefix + "exp-20270312"},
		{name: "missing secret", token: tokenTestPrefix + "exp-20270312|"},
		{name: "empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseKsefTokenExpiryDate(tc.token)
			if got != tc.want || ok == tc.want.IsZero() {
				t.Fatalf("expiry date = %v, %t", got, ok)
			}
		})
	}
}

func TestGenerateKsefToken(t *testing.T) {
	for _, tc := range []struct {
		name, token, expiry, requestDates string
		withDates                         bool
	}{
		{name: "explicit dates", token: tokenTestPrefix + "exp-20270312|secret", expiry: "2027-03-12",
			withDates: true, requestDates: `,"validFrom":"2027-01-06T08:00:00Z","validTo":"2027-03-12T12:00:00Z"`},
		{name: "default dates", token: tokenTestPrefix + "exp-20270312|secret", expiry: "2027-03-12"},
		{name: "legacy format", token: tokenTestPrefix + "secret"},
		{name: "unrecognized expiry", token: tokenTestPrefix + "exp-invalid|secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := newTestClient(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodPost || r.URL.Path != "/v2/tokens/rev2" {
					t.Fatalf("request = %s %s", r.Method, r.URL)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				assertJSONEqual(t, `{"permissions":["InvoiceRead"],"description":"Read invoices"`+tc.requestDates+`}`, body)
				return testJSONResponse(http.StatusAccepted, "application/json",
					fmt.Sprintf(`{"referenceNumber":%q,"token":%q}`, tokenTestReference, tc.token)), nil
			})
			req := tokenTestRequest()
			if tc.withDates {
				req.ValidFrom.SetTo(time.Date(2027, 1, 6, 8, 0, 0, 0, time.UTC))
				req.ValidTo.SetTo(time.Date(2027, 3, 12, 12, 0, 0, 0, time.UTC))
			}
			token, err := client.GenerateKsefToken(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if token.Token != tc.token || token.ReferenceNumber != tokenTestReference || calls != 1 {
				t.Fatalf("generation returned unexpected token data or request count (%d)", calls)
			}
			if tc.expiry == "" {
				if token.ExpiryDate != nil {
					t.Fatalf("expected unknown expiry, got %v", token.ExpiryDate)
				}
			} else if token.ExpiryDate == nil || token.ExpiryDate.Format(time.DateOnly) != tc.expiry {
				t.Fatalf("expiry date = %v, want %s", token.ExpiryDate, tc.expiry)
			}
		})
	}
}

func TestGetKsefTokenStatus(t *testing.T) {
	for _, tc := range []struct{ code, raw string }{
		{"AwaitingApproval", "AwaitingApproval"}, {"ApprovalExpired", "ApprovalExpired"},
		{"Active", "Active"}, {"NotYetActive", "NotYetActive"}, {"FutureValue", "NewStatus"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			client := newTestClient(t, func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet || r.URL.Path != "/v2/tokens/rev2/"+tokenTestReference {
					t.Fatalf("request = %s %s", r.Method, r.URL)
				}
				return testJSONResponse(http.StatusOK, "application/json", tokenStatusJSON(tc.code, tc.raw)), nil
			})
			got, err := client.GetKsefTokenStatus(context.Background(), tokenTestReference)
			if err != nil {
				t.Fatal(err)
			}
			if string(got.Status.Code) != tc.code || got.Status.RawCode != tc.raw || got.Status.DisplayName != "Status label" {
				t.Fatalf("status = %+v", got.Status)
			}
			if !got.ValidFrom.Equal(time.Date(2027, 1, 6, 8, 0, 0, 0, time.UTC)) ||
				!got.ValidTo.Equal(time.Date(2027, 3, 12, 13, 15, 16, 123456700, time.UTC)) {
				t.Fatalf("validity = %v to %v", got.ValidFrom, got.ValidTo)
			}
		})
	}
}

func TestApproveKsefToken(t *testing.T) {
	client := newTestClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.URL.Path != "/v2/tokens/"+tokenTestReference+"/approve" {
			t.Fatalf("request = %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatal("missing approver's bearer")
		}
		return testJSONResponse(http.StatusNoContent, "", ""), nil
	})
	if err := client.ApproveKsefToken(context.Background(), tokenTestReference); err != nil {
		t.Fatal(err)
	}
}
