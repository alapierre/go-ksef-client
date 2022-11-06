package model

type TokenRequestDTO struct {
	Identifier string
	Token      []byte
	Challenge  string
	Encryption EncryptionDTO
}

type EncryptionDTO struct {
	Enabled bool
	Key     []byte
	IV      []byte
}

type UpoDTO struct {
	ReferenceNumber       string
	ProcessingCode        int
	ProcessingDescription string
	Upo                   []byte
}
