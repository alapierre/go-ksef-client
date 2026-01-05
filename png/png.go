package png

import "github.com/skip2/go-qrcode"

func Qr(content string) ([]byte, error) {
	return qrcode.Encode(content, qrcode.Medium, 300)
}
