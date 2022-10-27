package api

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"go-ksef/ksef/model"
	"go-ksef/ksef/util"
	"testing"
)

var identifier = util.GetEnvOrFailed("KSEF_NIP")
var token = util.GetEnvOrFailed("KSEF_TOKEN")

var loginToKsef = true

func TestMain(m *testing.M) {

	fmt.Println("Test Main")

	setup()
	m.Run()
	teardown()
}

var apiClient Client
var session SessionService
var invoiceService InvoiceService
var sessionToken *model.TokenResponse

func setup() {

	log.Debug("initializing test")

	if util.DebugEnabled() {
		log.SetLevel(log.DebugLevel)
	}
	log.SetFormatter(&log.TextFormatter{
		DisableColors: false,
		FullTimestamp: true,
		ForceColors:   true,
	})

	apiClient = New(Test)
	session = NewSessionService(apiClient)
	invoiceService = NewInvoiceService(apiClient)

	if loginToKsef {
		log.Debug("logging into KSeF")

		var err error
		sessionToken, err = session.LoginByToken(
			identifier,
			model.ONIP,
			token,
			"../../data/mfkeys/test/publicKey.pem")

		if err != nil {
			log.Errorf("can't login %v", err)
		}
	}
}

func teardown() {

}
