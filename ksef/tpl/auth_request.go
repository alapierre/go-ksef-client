package tpl

import (
	"bytes"
	"text/template"
)

type AuthRequestData struct {
	Challenge             string
	Identifier            string
	SubjectIdentifierType string
	AllowedIPs            []string
}

func RenderAuthRequestXML(data AuthRequestData) ([]byte, error) {
	tpl, err := template.New("auth").Parse(authRequestTemplate)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
