package ksef

import (
	"context"
	"fmt"

	"github.com/alapierre/go-ksef-client/ksef/api"
)

// GenerateCollectiveIdentifier creates an identifier for invoices issued by the same seller.
// The request must contain at least two invoices.
func (c *Client) GenerateCollectiveIdentifier(ctx context.Context, invoices []api.CollectiveIdentifierInvoice) (*api.GenerateCollectiveIdentifierResponse, error) {
	req := api.NewOptCollectiveIdentifiersPostReq(api.CollectiveIdentifiersPostReq{
		Invoices: invoices,
	})
	res, err := c.raw.CollectiveIdentifiersPost(ctx, req)
	if err != nil {
		return nil, err
	}
	switch v := res.(type) {
	case *api.GenerateCollectiveIdentifierResponseHeaders:
		return &v.Response, nil
	case *api.UnauthorizedProblemDetails:
		return nil, ErrUnauthorized
	case *api.ForbiddenProblemDetails:
		return nil, ErrForbidden
	case *api.ExceptionResponse:
		return nil, HandleAPIError(v)
	default:
		return nil, fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
	}
}

// GetCollectiveIdentifierInvoices returns one page of invoices for up to ten collective identifiers.
// Pass the returned continuation token with the same identifiers to fetch the next page.
func (c *Client) GetCollectiveIdentifierInvoices(ctx context.Context, identifiers []string, continuationToken api.OptString, pageSize api.OptInt32) (*api.CollectiveIdentifierInvoicesQueryResponse, error) {
	req := api.NewOptCollectiveIdentifiersInvoicesPostReq(api.CollectiveIdentifiersInvoicesPostReq{
		CollectiveIdentifierNumbers: identifiers,
	})
	params := api.CollectiveIdentifiersInvoicesPostParams{
		XContinuationToken: continuationToken,
		PageSize:           pageSize,
	}
	res, err := c.raw.CollectiveIdentifiersInvoicesPost(ctx, req, params)
	if err != nil {
		return nil, err
	}
	switch v := res.(type) {
	case *api.CollectiveIdentifierInvoicesQueryResponseHeaders:
		return &v.Response, nil
	case *api.UnauthorizedProblemDetails:
		return nil, ErrUnauthorized
	case *api.ForbiddenProblemDetails:
		return nil, ErrForbidden
	case *api.ExceptionResponse:
		return nil, HandleAPIError(v)
	default:
		return nil, fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
	}
}

// GetCollectiveIdentifiersByKsefNumber returns one page of collective identifiers containing an invoice.
func (c *Client) GetCollectiveIdentifiersByKsefNumber(ctx context.Context, ksefNumber string, continuationToken api.OptString, pageSize api.OptInt32) (*api.CollectiveIdentifiersByKsefNumberQueryResponse, error) {
	params := api.CollectiveIdentifiersKsefKsefNumberGetParams{
		KsefNumber:         api.KsefNumber(ksefNumber),
		XContinuationToken: continuationToken,
		PageSize:           pageSize,
	}
	res, err := c.raw.CollectiveIdentifiersKsefKsefNumberGet(ctx, params)
	if err != nil {
		return nil, err
	}
	switch v := res.(type) {
	case *api.CollectiveIdentifiersByKsefNumberQueryResponseHeaders:
		return &v.Response, nil
	case *api.UnauthorizedProblemDetails:
		return nil, ErrUnauthorized
	case *api.ForbiddenProblemDetails:
		return nil, ErrForbidden
	case *api.ExceptionResponse:
		return nil, HandleAPIError(v)
	default:
		return nil, fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
	}
}

// QueryCollectiveIdentifiers returns one page of collective identifiers matching the filters.
// Filters must specify a creation date range of at most 100 days.
func (c *Client) QueryCollectiveIdentifiers(ctx context.Context, filters api.CollectiveIdentifiersQueryPostReq, continuationToken api.OptString, pageSize api.OptInt32) (*api.CollectiveIdentifiersQueryResponse, error) {
	params := api.CollectiveIdentifiersQueryPostParams{
		XContinuationToken: continuationToken,
		PageSize:           pageSize,
	}
	res, err := c.raw.CollectiveIdentifiersQueryPost(ctx, api.NewOptCollectiveIdentifiersQueryPostReq(filters), params)
	if err != nil {
		return nil, err
	}
	switch v := res.(type) {
	case *api.CollectiveIdentifiersQueryResponseHeaders:
		return &v.Response, nil
	case *api.UnauthorizedProblemDetails:
		return nil, ErrUnauthorized
	case *api.ForbiddenProblemDetails:
		return nil, ErrForbidden
	case *api.ExceptionResponse:
		return nil, HandleAPIError(v)
	default:
		return nil, fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
	}
}
