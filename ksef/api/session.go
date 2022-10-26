package api

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"go-ksef/ksef/cipher"
	"go-ksef/ksef/model"
	"go-ksef/ksef/tpl"
	"go-ksef/ksef/util"
	"time"
)

type SessionService interface {
	AuthorisationChallenge(identifier string, identifierType model.IdentifierType) (*model.AuthorisationChallengeResponse, error)
	LoginByToken(identifier string, identifierType model.IdentifierType, token, keyFileName string) (*model.TokenResponse, error)
}

type Session struct {
	client Client
}

func NewSessionService(client Client) SessionService {
	return &Session{client: client}
}

func (s *Session) AuthorisationChallenge(identifier string, identifierType model.IdentifierType) (*model.AuthorisationChallengeResponse, error) {

	logrus.Debug("Authorisation challenge")

	res := &model.AuthorisationChallengeResponse{}

	err := s.client.PostJsonNoAuth(
		"/online/Session/AuthorisationChallenge",
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

func (s *Session) LoginByToken(identifier string, identifierType model.IdentifierType, token, keyFileName string) (*model.TokenResponse, error) {

	logrus.Debug("Login by token")

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
		Encryption: model.EncryptionDTO{
			Enabled: false,
		},
	}

	request, err := util.MergeTemplate(&tpl.InitSessionTokenRequest, dto)
	if err != nil {
		return nil, err
	}

	var response = model.TokenResponse{}
	err = s.client.PostXMLFromBytes("/online/Session/InitToken", request, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func encodeAuthToken(token string, challengeTimestamp time.Time, keyFileName string) ([]byte, error) {
	message := fmt.Sprintf("%s|%d", token, challengeTimestamp.UnixMilli())
	return cipher.RsaEncrypt([]byte(message), keyFileName)
}
