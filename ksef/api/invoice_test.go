package api

import (
	"encoding/json"
	"fmt"
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
