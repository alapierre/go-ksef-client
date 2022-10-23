package api

import "go-ksef/ksef/model"

type SessionService interface {
	AuthorisationChallenge(identifier string, identifierType model.IdentifierType) (*model.AuthorisationChallengeResponse, error)
	//InitSessionTokenCall(authToken []byte) (model.InitSignedResponse, error)
	//InitSessionSignedCall(signedRequest []byte) (model.InitSignedResponse, error)
}

type Session struct {
	client *Client
}

func NewSessionService(client *Client) SessionService {
	return Session{client: client}
}

func (s Session) AuthorisationChallenge(identifier string, identifierType model.IdentifierType) (*model.AuthorisationChallengeResponse, error) {

	res := &model.AuthorisationChallengeResponse{}

	_, err := s.client.PostJsonNoAuth(
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
