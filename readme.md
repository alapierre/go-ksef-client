# GO KSeF API Client Library

Inspired by `ksef-java-rest-client` project, based on Resty Go KSeF client

Very early project status

## Sample

### Authorisation Challenge

````go
package main

import (
	"fmt"
	"go-ksef/ksef/api"
	"go-ksef/ksef/model"
)

func main() {
	client := api.New(api.Test)
	session := api.NewSessionService(client)

	challenge, err := session.AuthorisationChallenge("3896717236", model.ONIP)
	if err != nil {
		panic(err)
	}

	fmt.Printf("res: %#v\n", challenge)
}
````