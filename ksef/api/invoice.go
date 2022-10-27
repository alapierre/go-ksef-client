package api

import (
	"crypto/sha256"
	"encoding/base64"
	"go-ksef/ksef/model"
)

type InvoiceService interface {
	SendInvoice(content []byte, token string) (model.SendInvoiceResponse, error)
}

type invoice struct {
	client Client
}

func NewInvoiceService(client Client) InvoiceService {
	return &invoice{client: client}
}

func (i *invoice) SendInvoice(content []byte, token string) (model.SendInvoiceResponse, error) {

	res := &model.SendInvoiceResponse{}
	err := i.client.PutJson("/online/Invoice/Send", token, prepareSendInvoiceRequest(content), res)

	return model.SendInvoiceResponse{}, err
}

func prepareSendInvoiceRequest(content []byte) *model.SendInvoiceRequest {

	digest := sha256.Sum256(content)
	digestBase64 := base64.StdEncoding.EncodeToString(digest[:])
	contentBase64 := base64.StdEncoding.EncodeToString(content)

	return &model.SendInvoiceRequest{
		InvoiceHash: model.InvoiceHash{
			HashSHA: model.HashSHA{
				Algorithm: "SHA-256",
				Encoding:  "Base64",
				Value:     digestBase64,
			},
			FileSize: len(content),
		},
		InvoicePayload: model.InvoicePayload{
			Type:        "plain",
			InvoiceBody: contentBase64,
		},
	}
}
