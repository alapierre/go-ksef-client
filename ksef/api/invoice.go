package api

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/alapierre/go-ksef-client/ksef/cipher"
	"github.com/alapierre/go-ksef-client/ksef/model"
	log "github.com/sirupsen/logrus"
)

type InvoiceService interface {
	SendInvoice(content []byte, token string) (*model.SendInvoiceResponse, error)
	EncryptAndSend(content []byte, cipher cipher.AesCipher, token string) (*model.SendInvoiceResponse, error)
	GetUpo(referenceNumber string) (*model.UpoDTO, error)
	GetInvoice(invoiceId, token string) ([]byte, error)
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

// GetUpo get official acknowledgment of sent invoices
func (i *invoice) GetUpo(referenceNumber string) (*model.UpoDTO, error) {

	log.Debugf("Getting UPO for referenceNumber: %s", referenceNumber)

	res := &model.StatusResponse{}
	endpoint := fmt.Sprintf("/common/Status/%s", referenceNumber)

	err := i.client.GetJsonNoAuth(endpoint, res)

	upo := &model.UpoDTO{
		ReferenceNumber:       res.ReferenceNumber,
		ProcessingCode:        res.ProcessingCode,
		ProcessingDescription: res.ProcessingDescription,
	}

	if res.Upo != "" {
		upo.Upo, err = base64.StdEncoding.DecodeString(res.Upo)
	}

	return upo, err
}

// GetInvoice load invoice by KSeF reference number
func (i *invoice) GetInvoice(invoiceId, token string) ([]byte, error) {
	log.Debugf("Getting invice by KSeF reference number: %s", invoiceId)
	endpoint := fmt.Sprintf("/online/Invoice/Get/%s", invoiceId)
	return i.client.Get(endpoint, token)
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
