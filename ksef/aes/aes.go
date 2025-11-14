package aes

import (
	"bytes"
	aes2 "crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

// GenerateRandom256BitsKey generuje losowy 256-bitowy klucz (32 bajty)
func GenerateRandom256BitsKey() ([]byte, error) {
	key := make([]byte, 32) // 256 bits = 32 bytes
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("błąd generowania losowego klucza: %w", err)
	}
	return key, nil
}

// GenerateRandom16BytesIv generuje losowy 16-bajtowy wektor inicjalizacji
func GenerateRandom16BytesIv() ([]byte, error) {
	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("błąd generowania losowego IV: %w", err)
	}
	return iv, nil
}

// EncryptBytesWithAES256CBCPKCS7 szyfruje content, używając AES-256-CBC z PKCS#7.
func EncryptBytesWithAES256CBCPKCS7(content, key, iv []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("nieprawidłowa długość klucza: %d, oczekiwano 32 bajty (AES-256)", len(key))
	}
	if len(iv) != aes2.BlockSize {
		return nil, fmt.Errorf("nieprawidłowa długość IV: %d, oczekiwano %d", len(iv), aes2.BlockSize)
	}

	block, err := aes2.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("NewCipher: %w", err)
	}

	padded := pkcs7Pad(content, aes2.BlockSize)
	out := make([]byte, len(padded))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(out, padded)
	return out, nil
}

func pkcs7Pad(src []byte, blockSize int) []byte {
	padLen := blockSize - (len(src) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}
	return append(src, bytes.Repeat([]byte{byte(padLen)}, padLen)...)
}

// EncryptFileAESCBCPKCS5 szyfruje plik wejściowy do wyjściowego (AES-256-CBC, PKCS5/7).
// Plik wyjściowy jest nadpisywany, jeśli istnieje.
func EncryptFileAESCBCPKCS5(inPath, outPath string, key, iv []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("klucz musi mieć 32 bajty (AES-256), ma %d", len(key))
	}
	if len(iv) != aes2.BlockSize {
		return fmt.Errorf("IV musi mieć %d bajtów, ma %d", aes2.BlockSize, len(iv))
	}

	in, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer in.Close()

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer func() {
		_ = out.Sync()
		_ = out.Close()
	}()

	block, err := aes2.NewCipher(key)
	if err != nil {
		return fmt.Errorf("NewCipher: %w", err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)

	// Bufor wielokrotności rozmiaru bloku (np. 64 KiB)
	const chunk = 64 * 1024
	buf := make([]byte, chunk)
	var carry []byte // ewentualny niedomiar dopełniany przy kolejnym czytaniu

	for {
		n, rErr := in.Read(buf)
		if n > 0 {
			data := append(carry, buf[:n]...)
			// Ile pełnych bloków możemy zaszyfrować teraz?
			fullLen := (len(data) / aes2.BlockSize) * aes2.BlockSize
			// Zostaw ostatni niepełny (albo zero) do carry
			toEnc := data[:fullLen]
			carry = data[fullLen:]

			if len(toEnc) > 0 {
				if err := encryptAndWriteCBC(out, mode, toEnc); err != nil {
					return fmt.Errorf("write encrypted: %w", err)
				}
			}
		}
		if rErr == io.EOF {
			break
		}
		if rErr != nil {
			return fmt.Errorf("read input: %w", rErr)
		}
	}

	// Dodaj PKCS#5/7 padding do ostatniego fragmentu (carry)
	padLen := aes2.BlockSize - (len(carry) % aes2.BlockSize)
	if padLen == 0 {
		padLen = aes2.BlockSize
	}
	for i := 0; i < padLen; i++ {
		carry = append(carry, byte(padLen))
	}
	// Teraz carry ma pełną liczbę bloków
	if err := encryptAndWriteCBC(out, mode, carry); err != nil {
		return fmt.Errorf("write final encrypted: %w", err)
	}

	return nil
}

func encryptAndWriteCBC(w io.Writer, mode cipher.BlockMode, src []byte) error {
	if len(src)%mode.BlockSize() != 0 {
		return fmt.Errorf("długość danych (%d) nie jest wielokrotnością rozmiaru bloku (%d)", len(src), mode.BlockSize())
	}
	dst := make([]byte, len(src))
	mode.CryptBlocks(dst, src)
	_, err := w.Write(dst)
	return err
}

// DecryptBytesAESCBCPKCS5 odszyfrowuje bufor AES-256-CBC z PKCS5/7.
func DecryptBytesAESCBCPKCS5(ciphertext, key, iv []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("klucz musi mieć 32 bajty (AES-256), ma %d", len(key))
	}
	if len(iv) != aes2.BlockSize {
		return nil, fmt.Errorf("IV musi mieć %d bajtów, ma %d", aes2.BlockSize, len(iv))
	}
	if len(ciphertext)%aes2.BlockSize != 0 {
		return nil, fmt.Errorf("dane nie są wielokrotnością rozmiaru bloku")
	}

	block, err := aes2.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("NewCipher: %w", err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)

	plain := make([]byte, len(ciphertext))
	mode.CryptBlocks(plain, ciphertext)

	// PKCS7 unpad z walidacją
	if len(plain) == 0 {
		return nil, fmt.Errorf("puste dane po deszyfrowaniu")
	}
	pad := int(plain[len(plain)-1])
	if pad <= 0 || pad > aes2.BlockSize || pad > len(plain) {
		return nil, fmt.Errorf("niepoprawny padding")
	}
	// sprawdź wszystkie bajty paddingu
	for i := 0; i < pad; i++ {
		if plain[len(plain)-1-i] != byte(pad) {
			return nil, fmt.Errorf("niepoprawny padding")
		}
	}
	return plain[:len(plain)-pad], nil
}

// DecryptFileAESCBCPKCS5 odszyfrowuje plik wejściowy do wyjściowego (AES-256-CBC, PKCS5/7).
// Plik wyjściowy jest nadpisywany, jeśli istnieje.
func DecryptFileAESCBCPKCS5(inPath, outPath string, key, iv []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("klucz musi mieć 32 bajty (AES-256), ma %d", len(key))
	}
	if len(iv) != aes2.BlockSize {
		return fmt.Errorf("IV musi mieć %d bajtów, ma %d", aes2.BlockSize, len(iv))
	}

	in, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer in.Close()

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	// jeśli błąd, usuń plik wynikowy
	defer func() {
		_ = out.Sync()
		_ = out.Close()
	}()

	block, err := aes2.NewCipher(key)
	if err != nil {
		return fmt.Errorf("NewCipher: %w", err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)

	const chunk = 64 * 1024
	if (chunk % aes2.BlockSize) != 0 {
		return fmt.Errorf("chunk size must be multiple of block size")
	}
	buf := make([]byte, chunk)

	// Trzymamy poprzedni blok, aby na końcu móc zweryfikować i usunąć padding,
	// a wcześniej zapisać wszystkie wcześniejsze bloki bez buforowania całego pliku.
	var prev []byte

	writeDecrypted := func(b []byte) error {
		// b musi być wielokrotnością bloku
		if len(b)%aes2.BlockSize != 0 {
			return fmt.Errorf("nieprawidłowa długość bloku do zapisu")
		}
		dst := make([]byte, len(b))
		mode.CryptBlocks(dst, b)
		_, err := out.Write(dst)
		return err
	}

	for {
		n, rErr := in.Read(buf)
		if n > 0 {
			chunkData := buf[:n]
			// jeśli mamy prev, dołącz go do początku i zachowaj ostatni blok
			if len(prev) > 0 {
				chunkData = append(prev, chunkData...)
				prev = nil
			}
			// jeśli długość nie jest wielokrotnością bloku, odetnij ostatni niepełny fragment do prev
			fullLen := (len(chunkData) / aes2.BlockSize) * aes2.BlockSize
			// Zostaw jeden blok na koniec do obsługi paddingu; ale tylko gdy nie EOF.
			// Nie możemy zapisywać ostatniego bloku od razu, bo nie wiemy, czy to ostatni blok całego pliku.
			if rErr != io.EOF {
				if fullLen >= aes2.BlockSize {
					prev = append([]byte{}, chunkData[fullLen-aes2.BlockSize:fullLen]...)
					fullLen -= aes2.BlockSize
				}
			}
			toDec := chunkData[:fullLen]
			tail := chunkData[fullLen:]
			if len(toDec) > 0 {
				if err := writeDecrypted(toDec); err != nil {
					return fmt.Errorf("write decrypted: %w", err)
				}
			}
			// tail może być niepełnym blokiem — zachowaj
			if len(tail) > 0 {
				prev = append(prev, tail...)
			}
		}
		if rErr == io.EOF {
			break
		}
		if rErr != nil {
			return fmt.Errorf("read input: %w", rErr)
		}
	}

	// Na końcu prev powinno zawierać ostatni pełny blok szyfrogramu (z paddingiem).
	if len(prev) == 0 || len(prev)%aes2.BlockSize != 0 {
		return fmt.Errorf("brak ostatniego bloku do usunięcia paddingu")
	}

	// Odszyfruj ostatni blok w pamięci, usuń padding i zapisz plain (bez paddingu).
	last := make([]byte, len(prev))
	mode.CryptBlocks(last, prev)

	if len(last) == 0 {
		return fmt.Errorf("puste dane po deszyfrowaniu")
	}
	pad := int(last[len(last)-1])
	if pad <= 0 || pad > aes2.BlockSize || pad > len(last) {
		return fmt.Errorf("niepoprawny padding")
	}
	for i := 0; i < pad; i++ {
		if last[len(last)-1-i] != byte(pad) {
			return fmt.Errorf("niepoprawny padding")
		}
	}
	last = last[:len(last)-pad]

	if len(last) > 0 {
		if _, err := out.Write(last); err != nil {
			return fmt.Errorf("write final plaintext: %w", err)
		}
	}

	return nil
}

func GetMetadata(file []byte) Metadata {
	sum := sha256.Sum256(file)
	return Metadata{
		Size:    int64(len(file)),
		HashSHA: sum[:], // 32 surowe bajty
	}
}

type Metadata struct {
	Size    int64
	HashSHA []byte // SHA-256 w Base64
}
