package api

import "fmt"

type RequestError struct {
	StatusCode   int
	Err          error
	Body         string
	ErrorDetails map[string]any
}

func (r *RequestError) Error() string {
	return fmt.Sprintf("status: %d err: %v message: %s", r.StatusCode, r.Err, r.Body)
}
