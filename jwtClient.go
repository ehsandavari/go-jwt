package jwt

import (
	"github.com/golang-jwt/jwt/v5"
)

//go:generate mockgen -destination=./mocks/jwtClient.go -package=mocks github.com/ehsandavari/go-jwt IJwtClient

type IJwtClient interface {
	VerifyToken(token, audience, issuer string) (bool, error)
	IClaims
}

type sJwtClient struct {
	publicKey any
	claims    sClaims
}

func NewJwtClient(publicKey string) IJwtClient {
	_jwtClient := &sJwtClient{
		publicKey: publicKey,
	}

	return _jwtClient
}

func (r *sJwtClient) VerifyToken(token, audience, issuer string) (bool, error) {
	parse, err := jwt.ParseWithClaims(token, &r.claims, func(token *jwt.Token) (any, error) {
		if err := r.parser(token.Method); err != nil {
			return nil, err
		}
		return r.publicKey, nil
	}, jwt.WithIssuedAt(), jwt.WithAudience(audience), jwt.WithIssuer(issuer))
	if err != nil {
		return false, err
	}
	return parse.Valid, nil
}

func (r *sJwtClient) parser(method jwt.SigningMethod) (err error) {
	switch method.(type) {
	case *jwt.SigningMethodHMAC:
		r.publicKey = []byte(r.publicKey.(string))
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
		if r.publicKey, err = jwt.ParseRSAPublicKeyFromPEM([]byte(r.publicKey.(string))); err != nil {
			return err
		}
	case *jwt.SigningMethodECDSA:
		if r.publicKey, err = jwt.ParseECPublicKeyFromPEM([]byte(r.publicKey.(string))); err != nil {
			return err
		}
	case *jwt.SigningMethodEd25519:
		if r.publicKey, err = jwt.ParseEdPublicKeyFromPEM([]byte(r.publicKey.(string))); err != nil {
			return err
		}
	default:
		return ErrInvalidMethod
	}
	return nil
}
