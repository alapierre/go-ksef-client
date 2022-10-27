package model

import "time"

type SendEncryptedInvoiceRequest struct {
	InvoiceHash    InvoiceHash             `json:"invoiceHash"`
	InvoicePayload EncryptedInvoicePayload `json:"invoicePayload"`
}

type SendInvoiceRequest struct {
	InvoiceHash    InvoiceHash    `json:"invoiceHash"`
	InvoicePayload InvoicePayload `json:"invoicePayload"`
}

type EncryptedInvoicePayload struct {
	Type                 string               `json:"type"`
	EncryptedInvoiceHash EncryptedInvoiceHash `json:"encryptedInvoiceHash"`
	EncryptedInvoiceBody string               `json:"encryptedInvoiceBody"`
}

type InvoicePayload struct {
	Type        string `json:"type"`
	InvoiceBody string `json:"invoiceBody"`
}

type HashSHA struct {
	Algorithm string `json:"algorithm"`
	Encoding  string `json:"encoding"`
	Value     string `json:"value"`
}

type InvoiceHash struct {
	HashSHA  HashSHA `json:"hashSHA"`
	FileSize int     `json:"fileSize"`
}

type EncryptedInvoiceHash struct {
	HashSHA  HashSHA `json:"hashSHA"`
	FileSize int     `json:"fileSize"`
}

type SendInvoiceResponse struct {
	Timestamp              time.Time `json:"timestamp"`
	ReferenceNumber        string    `json:"referenceNumber"`
	ProcessingCode         int       `json:"processingCode"`
	ProcessingDescription  string    `json:"processingDescription"`
	ElementReferenceNumber string    `json:"elementReferenceNumber"`
}
