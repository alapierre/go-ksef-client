# GO KSeF API client library

Inspired by `ksef-java-rest-client` project, based on Resty, KSeF API client for Go.

Very early project status

## Sample

### Login by authorisation token with no additional encryption

````go
package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"go-ksef/ksef/api"
	"go-ksef/ksef/model"
	"go-ksef/ksef/util"
)

func main() {
	client := api.New(api.Test)
	session := api.NewSessionService(client)

	sessionToken, err := session.LoginByToken(
		util.GetEnvOrFailed("KSEF_NIP"), 
		model.ONIP, 
		util.GetEnvOrFailed("KSEF_TOKEN"), 
		"data/mfkeys/test/publicKey.pem")

	if err != nil {
		re, ok := err.(*api.RequestError)
		if ok {
			log.Errorf("request error %d responce body %s", re.StatusCode, re.Body)
		}
		panic(err)
	}

	fmt.Printf("session token: %s\n", sessionToken.SessionToken.Token)
}
````

### Login by authorisation token with additional AES encryption

The only difference is to create session object with NewSessionServiceWithEncryption and pass initialized AES cipher

````go
        aes, err := cipher.AesWithRandomKey(32)
	if err != nil {
		panic("can't prepare AES Encryptor: " + err)
	}
	sessionEncrypted := NewSessionServiceWithEncryption(apiClient, aes)
````

Important: When session is open with encryption, all invoices have to be sent encrypted, and all incoming invoices will 
be encrypted with AES key given on init session call.

### Send invoice with no encryption

````go
package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"go-ksef/ksef/api"
	"go-ksef/ksef/model"
	"go-ksef/ksef/util"
	"os"
)

func main() {
	content, err := os.ReadFile("../../data/testing/faktura1.xml")
	if err != nil {
		panic(err)
	}

	client := api.New(api.Test)
	invoiceService := api.NewInvoiceService(client)

	sendInvoiceResp, err := invoiceService.SendInvoice(content, "_sessionToken_")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Invoice responce: %#v", *sendInvoiceResp)
}
````

### Send invoice with encryption

````go
package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"go-ksef/ksef/api"
	"go-ksef/ksef/cipher"
	"go-ksef/ksef/model"
	"go-ksef/ksef/util"
	"os"
)

func main() {
	
	content, err := os.ReadFile("../../data/testing/faktura1.xml")
	if err != nil {
	    panic(err)
	}

	aes, err := cipher.AesWithRandomKey(32)

	client := api.New(api.Test)
	invoiceService := api.NewInvoiceService(client)
	
	sessionEncrypted := api.NewSessionServiceWithEncryption(client, aes)

	sessionToken, err := sessionEncrypted.LoginByToken(
		util.GetEnvOrFailed("KSEF_NIP"), 
		model.ONIP,
		util.GetEnvOrFailed("KSEF_TOKEN"),
		"../../data/mfkeys/test/publicKey.pem")

	if err != nil {
	    panic(err)	
	}

	fmt.Printf("session token: %s\n", sessionToken.SessionToken.Token)

	sendInvoiceResp, err := invoiceService.EncryptAndSend(content, aes, sessionToken.SessionToken.Token)
	if err != nil {
	    panic(err)
	}

	fmt.Printf("Invoice responce: %#v", *sendInvoiceResp)
}
````

### Authorisation Challenge

````go
package main

import (
	"fmt"
	"go-ksef/ksef/api"
	"go-ksef/ksef/model"
	"go-ksef/ksef/util"
)

func main() {
	client := api.New(api.Test)
	session := api.NewSessionService(client)

	challenge, err := session.AuthorisationChallenge(util.GetEnvOrFailed("KSEF_NIP"), model.ONIP)
	if err != nil {
		panic(err)
	}

	fmt.Printf("res: %#v\n", challenge)
}
````

## Debug info

To enable log debug just set `KSEF_DEBUG=true` environment variable. 
To enable http trace info, just set `SEF_HTTP_TRACE=true` environment variable

## Tests

Tests require some environment variables to run:

- `KSEF_NIP` organization tax identifier
- `KSEF_TOKEN` authorisation token to KSeF test environment