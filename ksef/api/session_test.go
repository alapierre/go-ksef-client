package api

import (
	"encoding/base64"
	"fmt"
	log "github.com/sirupsen/logrus"
	"go-ksef/ksef/model"
	"go-ksef/ksef/util"
	"testing"
	"time"
)

var identifier = util.GetEnvOrFailed("KSEF_NIP")
var token = util.GetEnvOrFailed("KSEF_TOKEN")

func TestMain(m *testing.M) {
	setup()
	m.Run()
	teardown()
}

var apiClient Client
var session SessionService

func setup() {

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
}

func teardown() {

}

func TestAuthorisationChallenge(t *testing.T) {

	challenge, err := session.AuthorisationChallenge(identifier, model.ONIP)
	if err != nil {
		t.Errorf("błąd %v", err)
	}

	fmt.Printf("res: %#v\n", challenge)
}

func Test_encodeSessionToken(t *testing.T) {

	challengeTimestamp, err := time.Parse(time.RFC3339, "2022-10-23T17:53:52.560Z")
	if err != nil {
		t.Errorf("can't parse timestamp")
	}

	encrypted, err := encodeAuthToken(
		token,
		challengeTimestamp,
		"../../data/mfkeys/test/publicKey.pem")

	if err != nil {
		t.Errorf("can't encrypt")
	}

	fmt.Println(base64.StdEncoding.EncodeToString(encrypted))
}

func TestSessionLoginByToken(t *testing.T) {
	token, err := session.LoginByToken(
		identifier,
		model.ONIP,
		token,
		"../../data/mfkeys/test/publicKey.pem")

	if err != nil {
		t.Errorf("can't login %v", err)
	}

	fmt.Printf("%v", token)
}
