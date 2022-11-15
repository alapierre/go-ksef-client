package main

import (
	"fmt"
	"github.com/alapierre/go-ksef-client/ksef/api"
	"github.com/alapierre/go-ksef-client/ksef/model"
	"github.com/alapierre/go-ksef-client/ksef/util"
	log "github.com/sirupsen/logrus"
)

func main() {
	client := api.New(api.Test)
	session := api.NewSessionService(client)

	sessionToken, err := session.LoginByToken(util.GetEnvOrFailed("NIP"), model.ONIP, util.GetEnvOrFailed("TOKEN"), "data/mfkeys/test/publicKey.pem")

	if err != nil {
		re, ok := err.(*api.RequestError)
		if ok {
			log.Errorf("request error %d responce body %s", re.StatusCode, re.Body)
		}
		panic(err)
	}

	fmt.Printf("session token: %s\n", sessionToken.SessionToken.Token)
}
