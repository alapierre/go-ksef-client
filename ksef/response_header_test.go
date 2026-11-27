package ksef

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestObserveResponseHeader(t *testing.T) {
	ctx := Context(context.Background(), "1111111111")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ksef.example/v2/a%2Fb?token=private", nil)
	if err != nil {
		t.Fatal(err)
	}
	transportErr := errors.New("transport failed")
	for _, tc := range []struct {
		name   string
		status int
		values []string
		err    error
	}{
		{"warnings", 200, []string{"first | second", "third, fourth"}, nil},
		{"present empty", 400, []string{""}, nil},
		{"absent", 200, nil, nil},
		{"transport error", 0, nil, transportErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var response *http.Response
			if tc.err == nil {
				response = testJSONResponse(tc.status, "application/xml", "<invoice/>")
				for _, value := range tc.values {
					response.Header.Add(SystemWarningHeader, value)
				}
			}
			base := testRoundTripper(func(*http.Request) (*http.Response, error) { return response, tc.err })
			calls := 0
			transport := ObserveResponseHeader(base, "x-system-warning", func(gotCtx context.Context, h ResponseHeader) {
				calls++
				want := ResponseHeader{Method: "GET", Path: "/v2/a%2Fb", StatusCode: tc.status, Name: SystemWarningHeader, Values: tc.values}
				if gotCtx != ctx || !reflect.DeepEqual(h, want) {
					t.Fatalf("callback received context %v and header %+v, want %+v", gotCtx, h, want)
				}
				h.Values[0] = "listener changed its copy"
			})
			got, err := transport.RoundTrip(req)
			if got != response || err != tc.err {
				t.Fatalf("transport returned %v, %v", got, err)
			}
			wantCalls := 0
			if len(tc.values) > 0 {
				wantCalls = 1
				if values := got.Header.Values(SystemWarningHeader); !reflect.DeepEqual(values, tc.values) {
					t.Fatalf("response header changed to %v", values)
				}
			}
			if calls != wantCalls {
				t.Fatalf("callback ran %d times, want %d", calls, wantCalls)
			}
		})
	}
}

func TestHeaderListenersPreserveFacadeError(t *testing.T) {
	base := testRoundTripper(func(*http.Request) (*http.Response, error) {
		resp := testJSONResponse(http.StatusTooManyRequests, "application/json",
			`{"status":{"code":429,"description":"Too Many Requests","details":[]}}`)
		resp.Header.Set(SystemWarningHeader, "maintenance")
		resp.Header.Set("Retry-After", "7")
		return resp, nil
	})
	var warning, retryAfter string
	transport := ObserveResponseHeader(base, SystemWarningHeader, func(_ context.Context, h ResponseHeader) {
		warning = h.Values[0]
		panic("logging failed")
	})
	httpClient := &http.Client{Transport: ObserveResponseHeader(transport, "retry-after", func(_ context.Context, h ResponseHeader) {
		retryAfter = h.Values[0]
	})}
	auth, err := NewAuthFacade(Test, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	_, err = auth.GetChallenge(context.Background())
	var apiErr *ApiError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusTooManyRequests || apiErr.RetryAfter.Or(0) != 7 {
		t.Fatalf("unexpected facade error: %v", err)
	}
	if warning != "maintenance" || retryAfter != "7" {
		t.Fatalf("callbacks received warning %q and Retry-After %q", warning, retryAfter)
	}
}
