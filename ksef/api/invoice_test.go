package api

import (
	"encoding/json"
	"fmt"
	"github.com/alapierre/go-ksef-client/ksef/cipher"
	"github.com/alapierre/go-ksef-client/ksef/model"
	"os"
	"testing"
)

func Test_invoice_SendInvoice(t *testing.T) {

	content, err := os.ReadFile("../../data/testing/faktura1.xml")
	if err != nil {
		t.Errorf("Can't read invoice file")
	}

	sendInvoiceResp, err := invoiceService.SendInvoice(content, sessionToken.SessionToken.Token)
	if err != nil {
		t.Errorf("can't send invoice %v", err)
	}

	fmt.Printf("Invoice responce: %#v", sendInvoiceResp)
}

func Test_invoice_EncryptAndSend(t *testing.T) {

	content, err := os.ReadFile("../../data/testing/faktura1.xml")
	if err != nil {
		t.Errorf("Can't read invoice file")
	}

	aes, err := cipher.AesWithRandomKey(32)

	sessionEncrypted := NewSessionServiceWithEncryption(apiClient, aes)

	sessionToken, err := sessionEncrypted.LoginByToken(
		identifier,
		model.ONIP,
		token,
		"../../data/mfkeys/test/publicKey.pem")

	if err != nil {
		t.Errorf("can't login %v", err)
	}

	fmt.Printf("session token: %s\n", sessionToken.SessionToken.Token)

	sendInvoiceResp, err := invoiceService.EncryptAndSend(content, aes, sessionToken.SessionToken.Token)
	if err != nil {
		t.Errorf("can't send invoice %v", err)
	}

	fmt.Printf("Invoice responce: %#v", *sendInvoiceResp)
}

func Test_prepareSendInvoiceRequest(t *testing.T) {

	content, err := os.ReadFile("../../data/testing/faktura1.xml")
	if err != nil {
		t.Errorf("Can't read invoice file")
	}

	res := prepareSendInvoiceRequest(content)

	b, err := json.Marshal(res)
	if err != nil {
		t.Errorf("Error: %s", err)
	}

	fmt.Println(string(b))
}

func Test_prepareEncryptedSendInvoiceRequest(t *testing.T) {

	content, err := os.ReadFile("../../data/testing/faktura1.xml")
	if err != nil {
		t.Errorf("Can't read invoice file %v", err)
	}

	aes, err := cipher.AesWithRandomKey(32)
	if err != nil {
		t.Errorf("Can't read invoice file %v", err)
	}

	res, err := prepareEncryptedSendInvoiceRequest(content, aes)

	b, err := json.Marshal(res)
	if err != nil {
		t.Errorf("Error: %s", err)
	}

	fmt.Println(string(b))
}

func TestInvoiceGetUpo(t *testing.T) {

	upo, err := invoiceService.GetUpo("20221105-SE-841F12C904-BCAD0DC824-40")
	if err != nil {
		t.Errorf("Can't get upo %v", err)
	}

	fmt.Printf("ReferenceNumber: %s, ProcessingCode: %d, ProcessingDescription: %s\n", upo.ReferenceNumber, upo.ProcessingCode, upo.ProcessingDescription)

	err = os.WriteFile("../../upo.xml", upo.Upo, 0644)
	if err != nil {
		t.Errorf("Can't write upo %v\n", err)
	}

}

func Test_invoice_GetInvoice(t *testing.T) {

	resp, err := invoiceService.GetInvoice("3896717236-20221105-CC6837-2E0114-2C", sessionToken.SessionToken.Token)
	//resp, err := invoiceService.GetInvoice("3896717236-20221105-CC6837-2E0114-2C", "084f9eda0b39757ca3bc7363e7a82dd09843e0a586f2518c367486eb7217c263")
	if err != nil {
		t.Errorf("Can't write invoice %v\n", err)
	}

	fmt.Println(string(resp))
}
