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
	publicKey string
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
		publicKey, err := r.parser(token.Method)
		if err != nil {
			return nil, err
		}
		return publicKey, nil
	}, jwt.WithIssuedAt(), jwt.WithAudience(audience), jwt.WithIssuer(issuer))
	if err != nil {
		return false, err
	}
	return parse.Valid, nil
}

func (r *sJwtClient) parser(method jwt.SigningMethod) (publicKey any, err error) {
	switch method.(type) {
	case *jwt.SigningMethodHMAC:
		publicKey = []byte(r.publicKey)
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
		if publicKey, err = jwt.ParseRSAPublicKeyFromPEM([]byte(r.publicKey)); err != nil {
			return nil, err
		}
	case *jwt.SigningMethodECDSA:
		if publicKey, err = jwt.ParseECPublicKeyFromPEM([]byte(r.publicKey)); err != nil {
			return nil, err
		}
	case *jwt.SigningMethodEd25519:
		if publicKey, err = jwt.ParseEdPublicKeyFromPEM([]byte(r.publicKey)); err != nil {
			return nil, err
		}
	default:
		return nil, ErrInvalidMethod
	}
	return publicKey, nil
}
