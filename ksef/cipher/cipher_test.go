package cipher

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestRsaCipher(t *testing.T) {

	cipher, err := RsaCipher([]byte("Ala ma kota"), "../../data/mfkeys/test/publicKey.pem")
	if err != nil {
		t.Errorf("problem with encrypt %v", err)
	}

	fmt.Println(hex.EncodeToString(cipher))
}
