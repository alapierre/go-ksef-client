package ksef

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/alapierre/go-ksef-client/ksef/api"
)

// ResponseMetadata contains headers from a successful KSeF response.
// XSystemWarning.Get distinguishes an absent header from a present value.
// Methods returning an error return zero metadata; Retry-After is on ApiError.
type ResponseMetadata struct {
	XSystemWarning api.OptSystemWarning
}

func responseMetadata(v interface{ GetXSystemWarning() api.OptSystemWarning }) ResponseMetadata {
	return ResponseMetadata{XSystemWarning: v.GetXSystemWarning()}
}

// responseAPIError handles decoded error variants. exceptionStatus must come from
// the calling operation's contract, since ExceptionResponse has no HTTP status.
func responseAPIError(response any, exceptionStatus int) error {
	var result *ApiError
	body := response
	switch v := response.(type) {
	case *api.ExceptionResponse:
		result = HandleAPIError(v).(*ApiError)
		result.Status = exceptionStatus
	case *api.BadRequestProblemDetails:
		result = problemAPIError(http.StatusBadRequest, v)
		for _, detail := range v.Errors {
			result.Details = append(result.Details, ErrorDetail{
				Code: int(detail.Code), Message: detail.Description,
				Details: append([]string(nil), detail.Details.Value...),
			})
		}
	case *api.TooManyRequestsResponseHeaders:
		status := v.Response.Status
		result = &ApiError{
			Status: http.StatusTooManyRequests, Message: status.Description,
			RetryAfter: v.RetryAfter,
			Details: []ErrorDetail{{Code: status.Code, Message: status.Description,
				Details: append([]string(nil), status.Details...)}},
		}
		body = &v.Response
	case *api.TooManyRequestsProblemDetailsHeaders:
		result = problemAPIError(http.StatusTooManyRequests, &v.Response)
		result.RetryAfter = v.RetryAfter
		body = &v.Response
	case *api.UnauthorizedProblemDetails:
		result = problemAPIError(http.StatusUnauthorized, v)
		result.cause = ErrUnauthorized
	case *api.ForbiddenProblemDetails:
		result = problemAPIError(http.StatusForbidden, v)
		result.cause = ErrForbidden
	case *api.GoneProblemDetails:
		result = problemAPIError(http.StatusGone, v)
	default:
		return fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", response)
	}
	// Re-encode the decoded body to preserve diagnostic fields (e.g. traceId,
	// instance and security). This is not the original wire representation.
	result.Body, _ = json.Marshal(body)
	return result
}

func problemAPIError(status int, problem interface {
	GetTitle() string
	GetDetail() string
}) *ApiError {
	message := problem.GetDetail()
	if message == "" {
		message = problem.GetTitle()
	}
	if message == "" {
		message = http.StatusText(status)
	}
	return &ApiError{Status: status, Message: message}
}
