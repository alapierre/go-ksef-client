package api

import (
	"crypto/sha256"
	"encoding/base64"
	"go-ksef/ksef/cipher"
	"go-ksef/ksef/model"
)

type InvoiceService interface {
	SendInvoice(content []byte, token string) (*model.SendInvoiceResponse, error)
	EncryptAndSend(content []byte, cipher cipher.AesCipher, token string) (*model.SendInvoiceResponse, error)
}

type invoice struct {
	client Client
}

func NewInvoiceService(client Client) InvoiceService {
	return &invoice{client: client}
}

func (i *invoice) EncryptAndSend(content []byte, cipher cipher.AesCipher, token string) (*model.SendInvoiceResponse, error) {
	res := &model.SendInvoiceResponse{}

	req, err := prepareEncryptedSendInvoiceRequest(content, cipher)
	if err != nil {
		return nil, err
	}

	err = i.client.PutJson("/online/Invoice/Send", token, req, res)
	return res, err
}

func (i *invoice) SendInvoice(content []byte, token string) (*model.SendInvoiceResponse, error) {

	res := &model.SendInvoiceResponse{}
	err := i.client.PutJson("/online/Invoice/Send", token, prepareSendInvoiceRequest(content), res)

	return res, err
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

func prepareEncryptedSendInvoiceRequest(content []byte, cipher cipher.AesCipher) (*model.SendEncryptedInvoiceRequest, error) {

	digest := sha256.Sum256(content)
	digestBase64 := base64.StdEncoding.EncodeToString(digest[:])

	encrypted, err := cipher.Encrypt(content)
	if err != nil {
		return nil, err
	}

	encryptedDigest := sha256.Sum256(encrypted)
	encryptedDigestBase64 := base64.StdEncoding.EncodeToString(encryptedDigest[:])

	contentBase64 := base64.StdEncoding.EncodeToString(encrypted)

	return &model.SendEncryptedInvoiceRequest{
		InvoiceHash: model.InvoiceHash{
			HashSHA: model.HashSHA{
				Algorithm: "SHA-256",
				Encoding:  "Base64",
				Value:     digestBase64,
			},
			FileSize: len(content),
		},
		InvoicePayload: model.EncryptedInvoicePayload{
			Type: "encrypted",
			EncryptedInvoiceHash: model.EncryptedInvoiceHash{
				HashSHA: model.HashSHA{
					Algorithm: "SHA-256",
					Encoding:  "Base64",
					Value:     encryptedDigestBase64,
				},
				FileSize: len(encrypted),
			},
			EncryptedInvoiceBody: contentBase64,
		},
	}, nil
}
