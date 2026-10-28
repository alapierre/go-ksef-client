package ksef

import (
	"context"
	"net/http"

	"github.com/alapierre/go-ksef-client/ksef/api"
)

// GenerateCollectiveIdentifier creates an identifier for invoices issued by the same seller.
// The request must contain at least two invoices.
func (c *Client) GenerateCollectiveIdentifier(ctx context.Context, invoices []api.CollectiveIdentifierInvoice) (*api.GenerateCollectiveIdentifierResponse, error) {
	result, _, err := c.GenerateCollectiveIdentifierWithMetadata(ctx, invoices)
	return result, err
}

// GenerateCollectiveIdentifierWithMetadata is GenerateCollectiveIdentifier with successful response headers.
func (c *Client) GenerateCollectiveIdentifierWithMetadata(ctx context.Context, invoices []api.CollectiveIdentifierInvoice) (*api.GenerateCollectiveIdentifierResponse, ResponseMetadata, error) {
	req := api.NewOptCollectiveIdentifiersPostReq(api.CollectiveIdentifiersPostReq{
		Invoices: invoices,
	})
	res, err := c.raw.CollectiveIdentifiersPost(ctx, req)
	if err != nil {
		return nil, ResponseMetadata{}, err
	}
	switch v := res.(type) {
	case *api.GenerateCollectiveIdentifierResponseHeaders:
		return &v.Response, responseMetadata(v), nil
	default:
		return nil, ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}

// GetCollectiveIdentifierInvoices returns one page of invoices for up to ten collective identifiers.
// Pass the returned continuation token with the same identifiers to fetch the next page.
func (c *Client) GetCollectiveIdentifierInvoices(ctx context.Context, identifiers []string, continuationToken api.OptString, pageSize api.OptInt32) (*api.CollectiveIdentifierInvoicesQueryResponse, error) {
	result, _, err := c.GetCollectiveIdentifierInvoicesWithMetadata(ctx, identifiers, continuationToken, pageSize)
	return result, err
}

// GetCollectiveIdentifierInvoicesWithMetadata is GetCollectiveIdentifierInvoices with successful response headers.
func (c *Client) GetCollectiveIdentifierInvoicesWithMetadata(ctx context.Context, identifiers []string, continuationToken api.OptString, pageSize api.OptInt32) (*api.CollectiveIdentifierInvoicesQueryResponse, ResponseMetadata, error) {
	req := api.NewOptCollectiveIdentifiersInvoicesPostReq(api.CollectiveIdentifiersInvoicesPostReq{
		CollectiveIdentifierNumbers: identifiers,
	})
	params := api.CollectiveIdentifiersInvoicesPostParams{
		XContinuationToken: continuationToken,
		PageSize:           pageSize,
	}
	res, err := c.raw.CollectiveIdentifiersInvoicesPost(ctx, req, params)
	if err != nil {
		return nil, ResponseMetadata{}, err
	}
	switch v := res.(type) {
	case *api.CollectiveIdentifierInvoicesQueryResponseHeaders:
		return &v.Response, responseMetadata(v), nil
	default:
		return nil, ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}

// GetCollectiveIdentifiersByKsefNumber returns one page of collective identifiers containing an invoice.
func (c *Client) GetCollectiveIdentifiersByKsefNumber(ctx context.Context, ksefNumber string, continuationToken api.OptString, pageSize api.OptInt32) (*api.CollectiveIdentifiersByKsefNumberQueryResponse, error) {
	result, _, err := c.GetCollectiveIdentifiersByKsefNumberWithMetadata(ctx, ksefNumber, continuationToken, pageSize)
	return result, err
}

// GetCollectiveIdentifiersByKsefNumberWithMetadata is GetCollectiveIdentifiersByKsefNumber with successful response headers.
func (c *Client) GetCollectiveIdentifiersByKsefNumberWithMetadata(ctx context.Context, ksefNumber string, continuationToken api.OptString, pageSize api.OptInt32) (*api.CollectiveIdentifiersByKsefNumberQueryResponse, ResponseMetadata, error) {
	params := api.CollectiveIdentifiersKsefKsefNumberGetParams{
		KsefNumber:         api.KsefNumber(ksefNumber),
		XContinuationToken: continuationToken,
		PageSize:           pageSize,
	}
	res, err := c.raw.CollectiveIdentifiersKsefKsefNumberGet(ctx, params)
	if err != nil {
		return nil, ResponseMetadata{}, err
	}
	switch v := res.(type) {
	case *api.CollectiveIdentifiersByKsefNumberQueryResponseHeaders:
		return &v.Response, responseMetadata(v), nil
	default:
		return nil, ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}

// QueryCollectiveIdentifiers returns one page of collective identifiers matching the filters.
// Filters must specify a creation date range of at most 100 days.
func (c *Client) QueryCollectiveIdentifiers(ctx context.Context, filters api.CollectiveIdentifiersQueryPostReq, continuationToken api.OptString, pageSize api.OptInt32) (*api.CollectiveIdentifiersQueryResponse, error) {
	result, _, err := c.QueryCollectiveIdentifiersWithMetadata(ctx, filters, continuationToken, pageSize)
	return result, err
}

// QueryCollectiveIdentifiersWithMetadata is QueryCollectiveIdentifiers with successful response headers.
func (c *Client) QueryCollectiveIdentifiersWithMetadata(ctx context.Context, filters api.CollectiveIdentifiersQueryPostReq, continuationToken api.OptString, pageSize api.OptInt32) (*api.CollectiveIdentifiersQueryResponse, ResponseMetadata, error) {
	params := api.CollectiveIdentifiersQueryPostParams{
		XContinuationToken: continuationToken,
		PageSize:           pageSize,
	}
	res, err := c.raw.CollectiveIdentifiersQueryPost(ctx, api.NewOptCollectiveIdentifiersQueryPostReq(filters), params)
	if err != nil {
		return nil, ResponseMetadata{}, err
	}
	switch v := res.(type) {
	case *api.CollectiveIdentifiersQueryResponseHeaders:
		return &v.Response, responseMetadata(v), nil
	default:
		return nil, ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}
