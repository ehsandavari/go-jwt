package jwt

import (
	"github.com/golang-jwt/jwt/v5"
)

type IClaims interface {
	GetId() (string, error)
	GetUserId() (string, error)
	GetEmail() (string, error)
	GetEmailVerified() (bool, error)
	GetPhoneNumber() (string, error)
	GetPhoneNumberVerified() (bool, error)
}

type sClaims struct {
	Email               string `json:"email,omitempty"`
	EmailVerified       *bool  `json:"email_verified,omitempty"`
	PhoneNumber         string `json:"phone_number,omitempty"`
	PhoneNumberVerified *bool  `json:"phone_number_verified,omitempty"`
	jwt.RegisteredClaims
}

func (r *sJwt) GetId() (string, error) {
	return r.claims.ID, nil
}

func (r *sJwt) GetUserId() (string, error) {
	return r.claims.Subject, nil
}

func (r *sJwt) GetEmail() (string, error) {
	return r.claims.Email, nil
}

func (r *sJwt) GetEmailVerified() (bool, error) {
	return *r.claims.EmailVerified, nil
}

func (r *sJwt) GetPhoneNumber() (string, error) {
	return r.claims.PhoneNumber, nil
}

func (r *sJwt) GetPhoneNumberVerified() (bool, error) {
	return *r.claims.PhoneNumberVerified, nil
}
