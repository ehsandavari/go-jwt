package jwt

import (
	"github.com/golang-jwt/jwt/v5"
	"log"
)

//go:generate mockgen -destination=./mocks/jwtServer.go -package=mocks github.com/ehsandavari/go-jwt IJwtServer

type IJwtServer interface {
	GenerateToken(options ...OptionServer) (string, error)
	IJwtClient
}

type sJwtServer struct {
	jwt        *jwt.Token
	privateKey any
	sJwtClient
}

func NewJwtServer(algorithm, publicKey, privateKey string, options ...OptionServer) IJwtServer {
	_jwt := &sJwtServer{
		jwt:        jwt.New(jwt.GetSigningMethod(algorithm)),
		privateKey: privateKey,
	}
	_jwt.publicKey = publicKey

	for _, option := range options {
		option.apply(_jwt)
	}

	if err := _jwt.parser(_jwt.jwt.Method); err != nil {
		log.Fatalln(err)
	}

	return _jwt
}

func (r *sJwtServer) GenerateToken(options ...OptionServer) (string, error) {
	for _, option := range options {
		option.apply(r)
	}

	r.jwt.Claims = r.claims

	signingString, err := r.jwt.SignedString(r.privateKey)
	if err != nil {
		return "", err
	}

	return signingString, nil
}

func (r *sJwtServer) parser(method jwt.SigningMethod) (err error) {
	switch method.(type) {
	case *jwt.SigningMethodHMAC:
		r.privateKey = []byte(r.privateKey.(string))
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
		if r.privateKey, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(r.privateKey.(string))); err != nil {
			return err
		}
	case *jwt.SigningMethodECDSA:
		if r.privateKey, err = jwt.ParseECPrivateKeyFromPEM([]byte(r.privateKey.(string))); err != nil {
			return err
		}
	case *jwt.SigningMethodEd25519:
		if r.privateKey, err = jwt.ParseEdPrivateKeyFromPEM([]byte(r.privateKey.(string))); err != nil {
			return err
		}
	default:
		return ErrInvalidMethod
	}
	return nil
}
