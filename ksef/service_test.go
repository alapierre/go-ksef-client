package ksef

import (
	_ "embed"
	"encoding/base64"
	"go-ksef/ksef/model"
	"html/template"
	"os"
	"testing"
)

//go:embed InitSessionTokenRequest.xml
var res string

func Test_gen(t *testing.T) {

	request := model.TokenRequestDTO{
		Nip:   "6891152920",
		Token: "alamakota123",
	}

	var funcMap = template.FuncMap{
		"base64": base64.StdEncoding.EncodeToString,
	}

	tmpl, err := template.New("test").Funcs(funcMap).Parse(res)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(os.Stdout, request)
	if err != nil {
		panic(err)
	}

}
