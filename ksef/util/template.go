package util

import (
	"bytes"
	"encoding/base64"
	"text/template"
)

func MergeTemplate(tpl *string, model any) ([]byte, error) {

	var funcMap = template.FuncMap{
		"base64": base64.StdEncoding.EncodeToString,
	}

	tmpl, err := template.New("request").Funcs(funcMap).Parse(*tpl)
	if err != nil {
		return nil, err
	}

	var output bytes.Buffer

	err = tmpl.Execute(&output, model)
	if err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
