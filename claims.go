package jwt

import (
	"github.com/golang-jwt/jwt/v5"
)

type IClaims interface {
	GetId() string
	GetUserId() string
	GetEmail() string
	GetEmailVerified() bool
	GetPhoneNumber() string
	GetPhoneNumberVerified() bool
}

type sClaims struct {
	Email               string `json:"email,omitempty"`
	EmailVerified       *bool  `json:"email_verified,omitempty"`
	PhoneNumber         string `json:"phone_number,omitempty"`
	PhoneNumberVerified *bool  `json:"phone_number_verified,omitempty"`
	jwt.RegisteredClaims
}

func (r *sJwtClient) GetId() string {
	return r.claims.ID
}

func (r *sJwtClient) GetUserId() string {
	return r.claims.Subject
}

func (r *sJwtClient) GetEmail() string {
	return r.claims.Email
}

func (r *sJwtClient) GetEmailVerified() bool {
	return *r.claims.EmailVerified
}

func (r *sJwtClient) GetPhoneNumber() string {
	return r.claims.PhoneNumber
}

func (r *sJwtClient) GetPhoneNumberVerified() bool {
	return *r.claims.PhoneNumberVerified
}
