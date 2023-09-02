package jwt

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"
)

//go:generate mockgen -destination=./mocks/jwtClient.go -package=mocks github.com/ehsandavari/go-jwt IJwtClient

type IJwtClient interface {
	VerifyToken(token, audience, issuer string) (bool, error)
	GinMiddleware() gin.HandlerFunc
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

func (r *sJwtClient) GinMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authorization := ctx.GetHeader("authorization")
		if len(authorization) == 0 {
			ctx.Status(http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authorization, "Bearer ")
		if token == authorization {
			ctx.Status(http.StatusUnauthorized)
			return
		}

		valid, err := r.VerifyToken(token, "", "")
		if err != nil {
			ctx.Status(http.StatusUnauthorized)
			return
		}

		if !valid {
			ctx.Status(http.StatusUnauthorized)
			return
		}
		ctx.Set(ContextKeyUserID, r.GetUserId())
		if len(r.GetEmail()) != 0 {
			ctx.Set(ContextKeyEmail, r.GetEmail())
			ctx.Set(ContextKeyEmailVerified, r.GetEmailVerified())
		}
		if len(r.GetPhoneNumber()) != 0 {
			ctx.Set(ContextKeyPhoneNumber, r.GetPhoneNumber())
			ctx.Set(ContextKeyPhoneNumberVerified, r.GetPhoneNumberVerified())
		}
	}
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
