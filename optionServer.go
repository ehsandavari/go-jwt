package jwt

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type OptionServer interface {
	apply(_jwt *sJwtServer)
}

type optionServerFunc func(*sJwtServer)

func (f optionServerFunc) apply(_jwt *sJwtServer) {
	f(_jwt)
}

func WithIssuer(issuer string) OptionServer {
	return optionServerFunc(func(_jwt *sJwtServer) {
		_jwt.claims.Issuer = issuer
	})
}

func WithAudience(audience ...string) OptionServer {
	return optionServerFunc(func(_jwt *sJwtServer) {
		_jwt.claims.Audience = audience
	})
}

func WithExpiresAt(expiresAt time.Time) OptionServer {
	return optionServerFunc(func(_jwt *sJwtServer) {
		_jwt.claims.ExpiresAt = jwt.NewNumericDate(expiresAt)
	})
}

func WithNotBefore(notBefore time.Time) OptionServer {
	return optionServerFunc(func(_jwt *sJwtServer) {
		_jwt.claims.NotBefore = jwt.NewNumericDate(notBefore)
	})
}

func WithIssuedAt(issuedAt time.Time) OptionServer {
	return optionServerFunc(func(_jwt *sJwtServer) {
		_jwt.claims.IssuedAt = jwt.NewNumericDate(issuedAt)
	})
}

func WithID(id string) OptionServer {
	return optionServerFunc(func(_jwt *sJwtServer) {
		_jwt.claims.ID = id
	})
}

func WithEmail(email string, emailVerified bool) OptionServer {
	return optionServerFunc(func(_jwt *sJwtServer) {
		if len(email) == 0 {
			_jwt.claims.Email = ""
			_jwt.claims.EmailVerified = nil
			return
		}
		_jwt.claims.Email = email
		_jwt.claims.EmailVerified = &emailVerified
	})
}

func WithPhoneNumber(phoneNumber string, phoneNumberVerified bool) OptionServer {
	return optionServerFunc(func(_jwt *sJwtServer) {
		if len(phoneNumber) == 0 {
			_jwt.claims.PhoneNumber = ""
			_jwt.claims.PhoneNumberVerified = nil
			return
		}
		_jwt.claims.PhoneNumber = phoneNumber
		_jwt.claims.PhoneNumberVerified = &phoneNumberVerified
	})
}
