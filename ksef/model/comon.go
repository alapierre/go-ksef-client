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

// StatusResponse response for invoice processing status (with UPO)
type StatusResponse struct {
	ProcessingCode        int       `json:"processingCode"`
	ProcessingDescription string    `json:"processingDescription"`
	ReferenceNumber       string    `json:"referenceNumber"`
	Timestamp             time.Time `json:"timestamp"`
	Upo                   string    `json:"upo"`
}

// InvoiceRequestKSeF request for invoice without authentication
type InvoiceRequestKSeF struct {
	InvoiceDetails struct {
		DueValue              string `json:"dueValue"`
		InvoiceOriginalNumber string `json:"invoiceOryginalNumber"`
		SubjectTo             struct {
			IssuedToIdentifier struct {
				Type string `json:"type"`
			} `json:"issuedToIdentifier"`
			IssuedToName struct {
				TradeName string `json:"tradeName"`
				Type      string `json:"type"`
			} `json:"issuedToName"`
		} `json:"subjectTo"`
	} `json:"invoiceDetails"`
	KsefReferenceNumber string `json:"ksefReferenceNumber"`
}
