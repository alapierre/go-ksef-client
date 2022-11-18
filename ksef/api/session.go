package api

import (
	"fmt"
	"github.com/alapierre/go-ksef-client/ksef/cipher"
	"github.com/alapierre/go-ksef-client/ksef/model"
	"github.com/alapierre/go-ksef-client/ksef/tpl"
	"github.com/alapierre/go-ksef-client/ksef/util"
	log "github.com/sirupsen/logrus"
	"time"
)

type SessionService interface {
	AuthorisationChallenge(identifier string, identifierType model.IdentifierType) (*model.AuthorisationChallengeResponse, error)
	LoginByToken(identifier string, identifierType model.IdentifierType, token, keyFileName string) (*model.TokenResponse, error)
	Status(pageSize, offset int, token string) (*model.SessionStatusResponse, error)
	StatusByReferenceNumber(pageSize, offset int, referenceNumber, token string) (*model.SessionStatusResponse, error)
	Terminate(token string) (*model.TerminateSessionResponse, error)
}

type session struct {
	client    Client
	aesCipher cipher.AesCipher
}

// NewSessionService prepare session without any encryption
func NewSessionService(client Client) SessionService {
	return &session{client: client}
}

// NewSessionServiceWithEncryption prepare session with AES encryption
func NewSessionServiceWithEncryption(client Client, aesCipher cipher.AesCipher) SessionService {
	return &session{client: client, aesCipher: aesCipher}
}

// AuthorisationChallenge call KSeF for authorization challenge
func (s *session) AuthorisationChallenge(identifier string, identifierType model.IdentifierType) (*model.AuthorisationChallengeResponse, error) {

	log.Debug("Authorisation challenge")

	res := &model.AuthorisationChallengeResponse{}

	err := s.client.PostJsonNoAuth(
		"/online/session/AuthorisationChallenge",
		model.AuthorisationChallengeRequest{
			ContextIdentifier: model.ContextIdentifier{
				Type:       identifierType,
				Identifier: identifier,
			}}, res)
	if err != nil {
		return nil, err
	}

	return res, nil
}

// LoginByToken opens new interactive season with given authorisation token
func (s *session) LoginByToken(identifier string, identifierType model.IdentifierType, token, keyFileName string) (*model.TokenResponse, error) {

	log.Debug("Login by token")

	challenge, err := s.AuthorisationChallenge(identifier, identifierType)
	if err != nil {
		return nil, err
	}

	authToken, err := encodeAuthToken(token, challenge.Timestamp, keyFileName)
	if err != nil {
		return nil, err
	}

	dto := model.TokenRequestDTO{
		Identifier: identifier,
		Token:      authToken,
		Challenge:  challenge.Challenge,
		Encryption: s.prepareEncryption(keyFileName),
	}

	request, err := util.MergeTemplate(&tpl.InitSessionTokenRequest, dto)
	if err != nil {
		return nil, err
	}

	var response = &model.TokenResponse{}
	err = s.client.PostXMLFromBytes("/online/session/InitToken", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Status gets current session status with sent invoices list
func (s *session) Status(pageSize, offset int, token string) (*model.SessionStatusResponse, error) {

	log.Debug("Current session status")

	var response = &model.SessionStatusResponse{}
	endpoint := fmt.Sprintf("/online/session/Status?PageSize=%d&PageOffset=%d", pageSize, offset)
	err := s.client.GetJson(endpoint, token, response)
	if err != nil {
		return nil, err
	}
	return response, nil
}

// StatusByReferenceNumber gets session status for given session reference number
func (s *session) StatusByReferenceNumber(pageSize, offset int, referenceNumber, token string) (*model.SessionStatusResponse, error) {

	log.Debugf("session status by reference number: %s", referenceNumber)

	var response = &model.SessionStatusResponse{}
	endpoint := fmt.Sprintf("/online/session/Status/%s?PageSize=%d&PageOffset=%d", referenceNumber, pageSize, offset)
	err := s.client.GetJson(endpoint, token, response)
	if err != nil {
		return nil, err
	}
	return response, nil
}

// Terminate close current interactive session
func (s *session) Terminate(token string) (*model.TerminateSessionResponse, error) {
	log.Debug("Terminate current session")

	var response = &model.TerminateSessionResponse{}
	endpoint := "/online/session/Terminate"

	err := s.client.GetJson(endpoint, token, response)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (s *session) prepareEncryption(keyFileName string) model.EncryptionDTO {
	enc := model.EncryptionDTO{}
	if s.aesCipher != nil {

		key, err := cipher.RsaEncrypt(s.aesCipher.Key(), keyFileName)
		if err != nil {
			panic(err)
		}

		enc.Enabled = true
		enc.Key = key
		enc.IV = s.aesCipher.Iv()
	} else {
		enc.Enabled = false
	}
	return enc
}

func encodeAuthToken(token string, challengeTimestamp time.Time, keyFileName string) ([]byte, error) {
	message := fmt.Sprintf("%s|%d", token, challengeTimestamp.UnixMilli())
	return cipher.RsaEncrypt([]byte(message), keyFileName)
}
