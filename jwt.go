package jwt

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"log"
)

//go:generate mockgen -destination=./mocks/jwt.go -package=mocks github.com/ehsandavari/go-logger ILogger

var (
	ErrInvalidAlgorithm = errors.New("algorithm is invalid")
)

type IJwt interface {
	GenerateToken(options ...Option) (string, error)
	VerifyToken(token string) (bool, error)
	IClaims
}

type sJwt struct {
	config     *sConfig
	jwt        *jwt.Token
	claims     sClaims
	publicKey  any
	privateKey any
}

func NewJwt(algorithm, publicKey, privateKey string, options ...Option) IJwt {
	_jwt := &sJwt{
		config: &sConfig{
			algorithm:  algorithm,
			publicKey:  publicKey,
			privateKey: privateKey,
		},
	}

	for _, option := range options {
		option.apply(_jwt)
	}

	if err := _jwt.parser(_jwt.config.algorithm); err != nil {
		log.Fatalln(err)
	}
	return _jwt
}

func (r *sJwt) GenerateToken(options ...Option) (string, error) {
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

func (r *sJwt) RefreshToken(token string) {
}

func (r *sJwt) VerifyToken(token string) (bool, error) {
	parse, err := jwt.ParseWithClaims(token, &r.claims, func(token *jwt.Token) (any, error) {
		err := r.parser(token.Method.Alg())
		if err != nil {
			return nil, err
		}
		return r.publicKey, nil
	}, jwt.WithValidMethods([]string{r.config.algorithm}), jwt.WithIssuedAt(), jwt.WithAudience(r.claims.Audience))
	if err != nil {
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return false, nil
		}
		return false, err
	}
	return parse.Valid, nil
}

func (r *sJwt) parser(algorithm string) (err error) {
	switch algorithm {
	case jwt.SigningMethodHS256.Alg(), jwt.SigningMethodHS384.Alg(), jwt.SigningMethodHS512.Alg():
		r.publicKey = []byte(r.config.publicKey)
		r.privateKey = []byte(r.config.privateKey)
	case jwt.SigningMethodRS256.Alg(), jwt.SigningMethodRS384.Alg(), jwt.SigningMethodRS512.Alg(),
		jwt.SigningMethodPS256.Alg(), jwt.SigningMethodPS384.Alg(), jwt.SigningMethodPS512.Alg():
		if r.publicKey, err = jwt.ParseRSAPublicKeyFromPEM([]byte(r.config.publicKey)); err != nil {
			return err
		}
		if len(r.config.privateKey) != 0 {
			if r.privateKey, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(r.config.privateKey)); err != nil {
				return err
			}
		}
	case jwt.SigningMethodES256.Alg(), jwt.SigningMethodES384.Alg(), jwt.SigningMethodES512.Alg():
		if r.publicKey, err = jwt.ParseECPublicKeyFromPEM([]byte(r.config.publicKey)); err != nil {
			return err
		}
		if len(r.config.privateKey) != 0 {
			if r.privateKey, err = jwt.ParseECPrivateKeyFromPEM([]byte(r.config.privateKey)); err != nil {
				return err
			}
		}
	case jwt.SigningMethodEdDSA.Alg():
		if r.publicKey, err = jwt.ParseEdPublicKeyFromPEM([]byte(r.config.publicKey)); err != nil {
			return err
		}
		if len(r.config.privateKey) != 0 {
			if r.privateKey, err = jwt.ParseEdPrivateKeyFromPEM([]byte(r.config.privateKey)); err != nil {
				return err
			}
		}
	default:
		return ErrInvalidAlgorithm
	}
	if r.jwt == nil {
		r.jwt = jwt.New(jwt.GetSigningMethod(algorithm))
	}
	return nil
}
