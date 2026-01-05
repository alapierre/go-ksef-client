package png

import (
	"os"
	"testing"
)

func TestWriteBytesToFile(t *testing.T) {

	content := "ala ma kota"
	data, err := Qr(content)
	if err != nil {
		t.Fatalf("failed to generate QR code: %v", err)
	}

	err = os.WriteFile("test-output.png", data, 0644)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
}
