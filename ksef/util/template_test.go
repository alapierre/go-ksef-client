package util

import (
	"fmt"
	"testing"
	"time"
)

var identifier = GetEnvOrFailed("KSEF_NIP")

func Test(t *testing.T) {

	output, err := ReplacePlaceholdersInXML("../../invoice_fa_3_type.xml", map[string]any{
		"NIP":        "1234567890",
		"ISSUE_DATE": time.Now(),
		"BUYER_NIP":  "0987654321",
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(string(output))

}
