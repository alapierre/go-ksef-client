package ksef

import (
	"context"
	"net/http"
	"slices"
)

// SystemWarningHeader is the HTTP response header for warnings issued by KSeF.
const SystemWarningHeader = "X-System-Warning"

// ResponseHeader describes the values of a selected header in one HTTP response.
type ResponseHeader struct {
	Method     string
	Path       string // Escaped request path, excluding the query string.
	StatusCode int
	Name       string   // Canonical HTTP header name.
	Values     []string // All values in response order, including empty strings.
}

// ObserveResponseHeader wraps base and calls observe once per response containing
// name, regardless of HTTP status. A nil base uses http.DefaultTransport.
// The callback runs synchronously and may be called concurrently by different
// requests. It owns its copy of Values. Callback panics are logged and isolated.
func ObserveResponseHeader(base http.RoundTripper, name string, observe func(context.Context, ResponseHeader)) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if observe == nil {
		return base
	}
	return &responseHeaderTransport{base: base, name: http.CanonicalHeaderKey(name), observe: observe}
}

type responseHeaderTransport struct {
	base    http.RoundTripper
	name    string
	observe func(context.Context, ResponseHeader)
}

func (t *responseHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	if values := resp.Header.Values(t.name); len(values) > 0 {
		t.notify(req.Context(), ResponseHeader{
			Method:     req.Method,
			Path:       req.URL.EscapedPath(),
			StatusCode: resp.StatusCode,
			Name:       t.name,
			Values:     slices.Clone(values),
		})
	}
	return resp, nil
}

func (t *responseHeaderTransport) notify(ctx context.Context, header ResponseHeader) {
	defer func() {
		if p := recover(); p != nil {
			logger.Warnf("Listener for response header %s panicked: %v", header.Name, p)
		}
	}()
	t.observe(ctx, header)
}

func (t *responseHeaderTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
