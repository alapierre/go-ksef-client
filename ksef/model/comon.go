package model

import "time"

type ExceptionResponse struct {
	Exception struct {
		ServiceCtx          string    `json:"serviceCtx"`
		ServiceCode         string    `json:"serviceCode"`
		ServiceName         string    `json:"serviceName"`
		Timestamp           time.Time `json:"timestamp"`
		ReferenceNumber     string    `json:"referenceNumber"`
		ExceptionDetailList []struct {
			ExceptionCode        int    `json:"exceptionCode"`
			ExceptionDescription string `json:"exceptionDescription"`
		} `json:"exceptionDetailList"`
	} `json:"exception"`
}
