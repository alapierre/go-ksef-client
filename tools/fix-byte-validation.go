//go:build ignore

// Fix ogen's validation of format: byte fields until ogen-go/ogen#1570 is resolved.
// OpenAPI string limits apply to the base64 representation, not decoded bytes.
package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"

	"golang.org/x/tools/go/ast/astutil"
)

func main() {
	const path = "ksef/api/oas_validators_gen.go"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		panic(err)
	}
	// These validators contain exactly one string conversion of a byte field.
	targets := map[string]bool{
		"AuthKsefTokenPostReq":             false,
		"InvoicesExportsPostReqEncryption": false,
		"PublicKeyCertificate":             false,
		"SessionsBatchPostReqEncryption":   false,
		"SessionsOnlinePostReqEncryption":  false,
		"Sha256HashBase64":                 false,
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Validate" || fn.Recv == nil {
			continue
		}
		receiver := fn.Recv.List[0].Type
		if ptr, ok := receiver.(*ast.StarExpr); ok {
			receiver = ptr.X
		}
		name, ok := receiver.(*ast.Ident)
		if !ok {
			continue
		}
		if _, ok := targets[name.Name]; !ok {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Validate" {
				return true
			}
			conversion, ok := call.Args[0].(*ast.CallExpr)
			if !ok || len(conversion.Args) != 1 {
				return true
			}
			var expr bytes.Buffer
			if err := format.Node(&expr, fset, conversion.Fun); err != nil {
				panic(err)
			}
			switch expr.String() {
			case "string":
				conversion.Fun = &ast.SelectorExpr{X: &ast.SelectorExpr{X: ast.NewIdent("base64"), Sel: ast.NewIdent("StdEncoding")}, Sel: ast.NewIdent("EncodeToString")}
				targets[name.Name] = true
			case "base64.StdEncoding.EncodeToString":
				targets[name.Name] = true
			}
			return true
		})
	}
	for name, found := range targets {
		if !found {
			panic(fmt.Sprintf("byte validator %s changed; review ogen workaround", name))
		}
	}
	astutil.AddImport(fset, file, "encoding/base64")
	var output bytes.Buffer
	if err := format.Node(&output, fset, file); err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, output.Bytes(), 0644); err != nil {
		panic(err)
	}
}
