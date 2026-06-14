package ksef

import (
	"errors"
	"testing"

	"github.com/alapierre/go-ksef-client/ksef/api"
)

func TestHandleAPIErrorKeepsHumanReadableDetails(t *testing.T) {
	err := HandleAPIError(&api.ExceptionResponse{
		Exception: api.NewOptNilExceptionInfo(api.ExceptionInfo{
			ExceptionDetailList: api.NewOptNilExceptionDetailsArray([]api.ExceptionDetails{
				{
					ExceptionCode:        api.NewOptInt32(21405),
					ExceptionDescription: api.NewOptNilString("Błąd walidacji danych wejściowych."),
					Details: api.NewOptNilStringArray([]string{
						"'dateRange.to' must be greater than or equal to 'dateRange.from'.",
					}),
				},
			}),
		}),
	})

	var apiErr *ApiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("HandleAPIError() returned %T, want *ApiError", err)
	}
	if got, want := apiErr.Message, "Błąd walidacji danych wejściowych."; got != want {
		t.Fatalf("Message = %q, want %q", got, want)
	}
	if got, want := len(apiErr.Details), 1; got != want {
		t.Fatalf("Details length = %d, want %d", got, want)
	}
	if got, want := apiErr.Details[0].Code, 21405; got != want {
		t.Fatalf("Code = %d, want %d", got, want)
	}
	if got, want := apiErr.Details[0].Details[0], "'dateRange.to' must be greater than or equal to 'dateRange.from'."; got != want {
		t.Fatalf("detail = %q, want %q", got, want)
	}
}
