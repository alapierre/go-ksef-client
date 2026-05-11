//go:build tools

package tools

import (
	_ "github.com/ogen-go/ogen/gen"
	_ "github.com/ogen-go/ogen/gen/ir"
	_ "golang.org/x/tools/go/packages"
	_ "golang.org/x/tools/imports"
)
