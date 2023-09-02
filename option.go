package jwt

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type Option interface {
	apply(_jwt *sJwt)
}

type optionFunc func(*sJwt)

func (f optionFunc) apply(_jwt *sJwt) {
	f(_jwt)
}

func WithIssuer(issuer string) Option {
	return optionFunc(func(_jwt *sJwt) {
		_jwt.claims.Issuer = issuer
	})
}

func WithSubject(subject string) Option {
	return optionFunc(func(_jwt *sJwt) {
		_jwt.claims.Subject = subject
	})
}

func WithAudience(audience []string) Option {
	return optionFunc(func(_jwt *sJwt) {
		_jwt.claims.Audience = audience
	})
}

func WithExpiresAt(expiresAt time.Time) Option {
	return optionFunc(func(_jwt *sJwt) {
		_jwt.claims.ExpiresAt = jwt.NewNumericDate(expiresAt)
	})
}

func WithNotBefore(notBefore time.Time) Option {
	return optionFunc(func(_jwt *sJwt) {
		_jwt.claims.NotBefore = jwt.NewNumericDate(notBefore)
	})
}

func WithIssuedAt(issuedAt time.Time) Option {
	return optionFunc(func(_jwt *sJwt) {
		_jwt.claims.IssuedAt = jwt.NewNumericDate(issuedAt)
	})
}

func WithID(id string) Option {
	return optionFunc(func(_jwt *sJwt) {
		_jwt.claims.ID = id
	})
}

func WithEmail(email string) Option {
	return optionFunc(func(_jwt *sJwt) {
		_jwt.claims.Email = email
	})
}

func WithEmailVerified(emailVerified bool) Option {
	return optionFunc(func(_jwt *sJwt) {
		_jwt.claims.EmailVerified = &emailVerified
	})
}

func WithPhoneNumber(phoneNumber string) Option {
	return optionFunc(func(_jwt *sJwt) {
		_jwt.claims.PhoneNumber = phoneNumber
	})
}

func WithPhoneNumberVerified(phoneNumberVerified bool) Option {
	return optionFunc(func(_jwt *sJwt) {
		_jwt.claims.PhoneNumberVerified = &phoneNumberVerified
	})
}
