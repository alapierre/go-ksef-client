package model

import "time"

type IdentifierType string

const (
	ONIP  IdentifierType = "onip"
	NIP                  = "nip"
	PESEL                = "pesel"
)

type ContextIdentifier struct {
	Type       IdentifierType `json:"type"`
	Identifier string         `json:"identifier"`
}

type AuthorisationChallengeRequest struct {
	ContextIdentifier ContextIdentifier `json:"contextIdentifier"`
}

type AuthorisationChallengeResponse struct {
	Timestamp time.Time `json:"timestamp"` // time format is time.RFC3339
	Challenge string    `json:"challenge"`
}

type AuthorisationToken struct {
	Timestamp              string `json:"timestamp"`
	ReferenceNumber        string `json:"referenceNumber"`
	ProcessingCode         string `json:"processingCode"`
	ProcessingDescription  string `json:"processingDescription"`
	ElementReferenceNumber string `json:"elementReferenceNumber"`
	AuthorisationToken     string `json:"authorisationToken"`
}

type InitSignedResponse struct {
	Timestamp       string       `json:"timestamp"`
	ReferenceNumber string       `json:"referenceNumber"`
	SessionToken    SessionToken `json:"sessionToken"`
}

type SessionToken struct {
	Token string `json:"token"`
}

type TokenResponse struct {
	Timestamp       time.Time `json:"timestamp"`
	ReferenceNumber string    `json:"referenceNumber"`
	SessionToken    struct {
		Token   string `json:"token"`
		Context struct {
			ContextIdentifier struct {
				Type       string `json:"type"`
				Identifier string `json:"identifier"`
			} `json:"contextIdentifier"`
			ContextName struct {
				Type      string      `json:"type"`
				TradeName interface{} `json:"tradeName"`
				FullName  string      `json:"fullName"`
			} `json:"contextName"`
			CredentialsRoleList []struct {
				Type            string `json:"type"`
				RoleType        string `json:"roleType"`
				RoleDescription string `json:"roleDescription"`
			} `json:"credentialsRoleList"`
		} `json:"context"`
	} `json:"sessionToken"`
}

type Context struct {
	ContextIdentifier   ContextIdentifier `json:"contextIdentifier"`
	ContextName         ContextName       `json:"contextName"`
	CredentialsRoleList []CredentialsRole `json:"credentialsRoleList"`
}

type ContextName struct {
	Type      string `json:"type"`
	TradeName string `json:"tradeName"`
	FullName  string `json:"fullName"`
}

type CredentialsRole struct {
	Type                  string                `json:"type"`
	RoleType              string                `json:"roleType"`
	RoleDescription       string                `json:"roleDescription"`
	RoleGrantorIdentifier RoleGrantorIdentifier `json:"roleGrantorIdentifier"`
}

type RoleGrantorIdentifier struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}
