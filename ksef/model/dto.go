package model

type TokenRequestDTO struct {
	Identifier string
	Token      []byte
	Challenge  string
}
