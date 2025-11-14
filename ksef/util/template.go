package util

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"os"
	"text/template"
	"time"
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

func ReplacePlaceholdersInXML(path string, placeholders map[string]any) ([]byte, error) {

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read XML file: %w", err)
	}

	var funcMap = template.FuncMap{
		"randomInvoiceNumber": RandomInvoiceNumber,
		"formatDate":          FormatDateYYYYMMDD,
	}

	tmpl, err := template.New("invoice").Option("missingkey=error").Funcs(funcMap).Parse(string(data))
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, placeholders); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func RandomInvoiceNumber(prefix string) string {
	now := time.Now()
	randomPart := rand.IntN(1000000) // 0..999999

	if prefix == "" {
		prefix = "FV"
	}

	return fmt.Sprintf(
		"%s %04d/%02d/%06d",
		prefix,
		now.Year(),
		int(now.Month()),
		randomPart,
	)
}

func FormatDateYYYYMMDD(t time.Time) string {
	return t.Format("2006-01-02")
}
