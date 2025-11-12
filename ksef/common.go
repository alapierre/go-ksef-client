package ksef

import (
	"context"
	"errors"
	"fmt"

	"github.com/alapierre/go-ksef-client/ksef/api"
)

type nipKey struct{}

func Context(ctx context.Context, nip string) context.Context {
	return context.WithValue(ctx, nipKey{}, nip)
}

func NipFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(nipKey{}).(string)
	return v, ok
}

var (
	// ErrUnauthorized ogólny marker dla 401
	ErrUnauthorized = errors.New("ksef unauthorized")
	Err500          = errors.New("ksef other error")
)

// ApiError błąd z kontekstem zdarzenia
type ApiError struct {
	Status  int // HTTP status (np. 401)
	Details []ErrorDetail
	Body    []byte // fragment body, do diagnostyki
	Message string
}

type ErrorDetail struct {
	Code    int
	Message string
}

func (e *ApiError) Error() string {
	return fmt.Sprintf("KSeF returns http status %d: %s", e.Status, e.Message)
}

func HandelOtherApiError(res interface{}) error {
	return fmt.Errorf("inny typ odpowiedzi błędu: %T", res)
}

// HandleAPIError obsługuje generyczne błędy API (4xx/5xx)
func HandleAPIError(response ExceptionValuer) error {

	ex := response.GetValue()

	// Stwórz podstawowy komunikat błędu
	errorMsg := fmt.Sprintf("błąd API: %s", ex.GetException().Value)

	var d []ErrorDetail

	// Sprawdź czy mamy listę szczegółów błędów
	if details, ok := ex.GetException().Value.ExceptionDetailList.Get(); ok && len(details) > 0 {

		errorMsg += "\nSzczegóły:"
		for i, detail := range details {
			errorMsg += fmt.Sprintf("\n  %d: %+v", i+1, detail)

			var (
				code int
				msg  string
			)

			if v, ok := detail.ExceptionCode.Get(); ok {
				code = int(v)
			}
			if s, ok := detail.ExceptionDescription.Get(); ok {
				msg = s
			}
			// Jeżeli brak opisu, spróbuj złożyć z tablicy Details
			if msg == "" {
				if arr, ok := detail.Details.Get(); ok && len(arr) > 0 {
					msg = arr[0]
				}
			}

			d = append(d, ErrorDetail{Message: msg, Code: code})
		}
	}

	return &ApiError{
		Status:  0,
		Details: d,
		Body:    nil,
		Message: errorMsg,
	}
}

type ExceptionValuer interface{ GetValue() *api.ExceptionResponse }
