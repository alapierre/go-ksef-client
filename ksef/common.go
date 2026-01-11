package ksef

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/alapierre/go-ksef-client/ksef/api"
	"github.com/sirupsen/logrus"
)

var logger = logrus.WithField("component", "ksef")

type nipKey struct{}
type forceAuthKey struct{}
type envKey struct{}

type authReference struct{}

func Context(ctx context.Context, nip string) context.Context {
	return context.WithValue(ctx, nipKey{}, nip)
}

func ContextWithForceAuth(ctx context.Context) context.Context {
	return context.WithValue(ctx, forceAuthKey{}, true)
}

func ContextWithEnv(ctx context.Context, nip string, e Environment) context.Context {
	c := context.WithValue(ctx, nipKey{}, nip)
	return context.WithValue(c, envKey{}, e)
}

func ContextWithAuthReference(ctx context.Context, ref string) context.Context {
	return context.WithValue(ctx, authReference{}, ref)
}

func NipFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(nipKey{}).(string)
	return v, ok
}

func IsForceAuth(ctx context.Context) bool {
	v, ok := ctx.Value(forceAuthKey{}).(bool)
	return ok && v
}

func EnvFromContext(ctx context.Context) (Environment, bool) {
	v, ok := ctx.Value(envKey{}).(Environment)
	return v, ok
}

func AuthReferenceFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(authReference{}).(string)
	return v, ok
}

var (
	// ErrUnauthorized ogólny marker dla 401
	ErrUnauthorized = errors.New("ksef unauthorized")
	ErrForbidden    = errors.New("ksef forbidden")
	Err500          = errors.New("ksef other error")
	ErrNoNip        = errors.New("no NIP in context.Context")
	ErrNoEnv        = errors.New("no KSeF environment in context.Context")
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

func (e *ErrorDetail) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}

func (e *ApiError) Error() string {
	return fmt.Sprintf("KSeF returns http status %d: %s", e.Status, e.Message)
}

func HandelOtherApiError(res interface{}) error {
	return fmt.Errorf("inny typ odpowiedzi błędu: %T", res)
}

// HandleAPIError obsługuje generyczne błędy API (4xx/5xx)
func HandleAPIError(ex *api.ExceptionResponse) error {

	// Stwórz podstawowy komunikat o błędzie
	errorMsg := fmt.Sprintf("błąd API: %v", ex.GetException().Value)

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

type Environment int

const (
	Test Environment = iota
	Demo
	Prod
)

func (e *Environment) BaseURL() string {
	switch *e {
	case Prod:
		return "https://api.ksef.mf.gov.pl/v2"
	case Test:
		return "https://api-test.ksef.mf.gov.pl/v2"
	case Demo:
		return "https://api-demo.ksef.mf.gov.pl/v2"
	}
	panic("Invalid environment")
}

func (e *Environment) Name() string {
	switch *e {
	case Prod:
		return "prod"
	case Test:
		return "test"
	case Demo:
		return "demo"
	}
	panic("Invalid environment")
}

func (e *Environment) UnmarshalText(text []byte) error {
	val := strings.ToLower(strings.TrimSpace(string(text)))

	switch val {
	case "prod":
		*e = Prod
	case "demo":
		*e = Demo
	case "test":
		*e = Test
	default:
		return fmt.Errorf("invalid KSEF_ENV: %q (allowed: prod, demo, test)", val)
	}
	return nil
}

type Nip string

type TokenRefresher interface {
	RefreshToken(ctx context.Context, refreshToken string) (api.TokenInfo, error)
}
