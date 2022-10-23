package api

import (
	"fmt"
	"go-ksef/ksef/model"
	"testing"
)

const identifier = "3896717236"

func TestNewSessionService(t *testing.T) {

	client := New(Test)
	session := NewSessionService(client)

	challenge, err := session.AuthorisationChallenge(identifier, model.ONIP)
	if err != nil {
		t.Errorf("błąd %v", err)
	}

	fmt.Printf("res: %#v\n", challenge)
}
