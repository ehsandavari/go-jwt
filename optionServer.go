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

func WithUserId(subject string) OptionServer {
	return optionServerFunc(func(_jwt *sJwtServer) {
		_jwt.claims.Subject = subject
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

func WithEmail(email string) OptionServer {
	return optionServerFunc(func(_jwt *sJwtServer) {
		_jwt.claims.Email = email
	})
}

func WithEmailVerified(emailVerified bool) OptionServer {
	return optionServerFunc(func(_jwt *sJwtServer) {
		_jwt.claims.EmailVerified = &emailVerified
	})
}

func WithPhoneNumber(phoneNumber string) OptionServer {
	return optionServerFunc(func(_jwt *sJwtServer) {
		_jwt.claims.PhoneNumber = phoneNumber
	})
}

func WithPhoneNumberVerified(phoneNumberVerified bool) OptionServer {
	return optionServerFunc(func(_jwt *sJwtServer) {
		_jwt.claims.PhoneNumberVerified = &phoneNumberVerified
	})
}
