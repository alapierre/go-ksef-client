package ksef

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/alapierre/go-ksef-client/ksef/api"
)

// GeneratedKsefToken contains the secret returned once by KSeF and its reference
// number for subsequent status and approval requests.
type GeneratedKsefToken struct {
	Token           string
	ReferenceNumber string
	// ExpiryDate is the embedded calendar day at midnight UTC, or nil if unknown.
	// GetKsefTokenStatus supplies the exact expiry timestamp in ValidTo.
	ExpiryDate *time.Time
}

// ParseKsefTokenExpiryDate reads the exp-YYYYMMDD field from a KSeF token.
// It returns the calendar day at midnight UTC and true when the field is valid.
// It can also be used on tokens received from the legacy generation endpoint.
func ParseKsefTokenExpiryDate(token string) (time.Time, bool) {
	// Format: reference|context|exp-YYYYMMDD|secret. Older tokens omit exp.
	fields := strings.SplitN(token, "|", 5)
	if len(fields) != 4 || fields[0] == "" || fields[1] == "" || fields[3] == "" {
		return time.Time{}, false
	}
	value, ok := strings.CutPrefix(fields[2], "exp-")
	if !ok {
		return time.Time{}, false
	}
	date, err := time.Parse("20060102", value)
	if err != nil {
		return time.Time{}, false
	}
	return date, true
}

// GenerateKsefToken requests a token through POST /tokens/rev2. Omit ValidFrom
// and ValidTo to use KSeF defaults. Persist the secret before querying status.
func (c *Client) GenerateKsefToken(ctx context.Context, req api.TokensRev2PostReq) (*GeneratedKsefToken, error) {
	result, _, err := c.GenerateKsefTokenWithMetadata(ctx, req)
	return result, err
}

// GenerateKsefTokenWithMetadata is GenerateKsefToken with successful response headers.
func (c *Client) GenerateKsefTokenWithMetadata(ctx context.Context, req api.TokensRev2PostReq) (*GeneratedKsefToken, ResponseMetadata, error) {
	res, err := c.raw.TokensRev2Post(ctx, api.NewOptTokensRev2PostReq(req))
	if err != nil {
		return nil, ResponseMetadata{}, err
	}
	switch v := res.(type) {
	case *api.GenerateTokenResponseRev2Headers:
		result := &GeneratedKsefToken{
			Token:           v.Response.Token,
			ReferenceNumber: string(v.Response.ReferenceNumber),
		}
		if date, ok := ParseKsefTokenExpiryDate(result.Token); ok {
			result.ExpiryDate = &date
		}
		return result, responseMetadata(v), nil
	default:
		return nil, ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}

// GetKsefTokenStatus retrieves the rev2 status and validity timestamps for a
// token generated through either revision. Only Active tokens can be used to log in.
func (c *Client) GetKsefTokenStatus(ctx context.Context, referenceNumber string) (*api.TokenStatusResponseRev2, error) {
	result, _, err := c.GetKsefTokenStatusWithMetadata(ctx, referenceNumber)
	return result, err
}

// GetKsefTokenStatusWithMetadata is GetKsefTokenStatus with successful response headers.
func (c *Client) GetKsefTokenStatusWithMetadata(ctx context.Context, referenceNumber string) (*api.TokenStatusResponseRev2, ResponseMetadata, error) {
	res, err := c.raw.TokensRev2ReferenceNumberGet(ctx, api.TokensRev2ReferenceNumberGetParams{
		ReferenceNumber: api.ReferenceNumber(referenceNumber),
	})
	if err != nil {
		return nil, ResponseMetadata{}, err
	}
	switch v := res.(type) {
	case *api.TokenStatusResponseRev2Headers:
		return &v.Response, responseMetadata(v), nil
	default:
		return nil, ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}

// ApproveKsefToken approves a token in AwaitingApproval. The client must use
// an authorized approver's session authenticated through XAdES or Węzeł Krajowy.
func (c *Client) ApproveKsefToken(ctx context.Context, referenceNumber string) error {
	_, err := c.ApproveKsefTokenWithMetadata(ctx, referenceNumber)
	return err
}

// ApproveKsefTokenWithMetadata is ApproveKsefToken with successful response headers.
func (c *Client) ApproveKsefTokenWithMetadata(ctx context.Context, referenceNumber string) (ResponseMetadata, error) {
	res, err := c.raw.TokensReferenceNumberApprovePost(ctx, api.TokensReferenceNumberApprovePostParams{
		ReferenceNumber: api.ReferenceNumber(referenceNumber),
	})
	if err != nil {
		return ResponseMetadata{}, err
	}
	switch v := res.(type) {
	case *api.TokensReferenceNumberApprovePostNoContent:
		return responseMetadata(v), nil
	default:
		return ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}
