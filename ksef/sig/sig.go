package sig

import (
	"context"
	"time"

	"github.com/alapierre/go-ksef-client/ksef"
	"github.com/alapierre/go-ksef-client/ksef/tpl"
	"github.com/alapierre/godss/signer"
	"github.com/alapierre/godss/xades"
	"github.com/beevik/etree"
)

func WithXades(ctx context.Context, authFacade *ksef.AuthFacade, s signer.Signer) (*ksef.AuthResult, error) {

	nip, ok := ksef.NipFromContext(ctx)
	if !ok || nip == "" {
		return nil, ksef.ErrNoNip
	}

	challenge, err := authFacade.GetChallenge(ctx)
	if err != nil {
		return nil, err
	}

	xml, err := tpl.RenderAuthRequestXML(tpl.AuthRequestData{
		Challenge:             string(challenge.Challenge),
		Identifier:            nip,
		SubjectIdentifierType: "certificateSubject"},
	)
	if err != nil {
		return nil, err
	}

	x := xades.NewDefault(s)
	doc := etree.NewDocument()
	err = doc.ReadFromBytes(xml)

	if err != nil {
		return nil, err
	}

	signedDoc, err := x.SignDocument(doc.Root())
	if err != nil {
		return nil, err
	}

	b, err := signedDoc.WriteToBytes()
	if err != nil {
		return nil, err
	}

	initResp, err := authFacade.AuthWithXades(ctx, b)
	if err != nil {
		return nil, err
	}

	ctx = ksef.ContextWithAuthReference(ctx, string(initResp.ReferenceNumber))
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	res, err := authFacade.AuthWaitAndRedeem(ctx, initResp, 1*time.Second)
	if err != nil {
		return nil, err
	}

	return &ksef.AuthResult{ReferenceNumber: string(initResp.ReferenceNumber), Tokens: res}, nil
}
