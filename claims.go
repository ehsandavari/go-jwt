package jwt

import (
	"github.com/golang-jwt/jwt/v5"
	"slices"
)

type IClaims interface {
	GetId() string
	GetUserId() string
	GetEmail() string
	GetEmailVerified() bool
	GetPhoneNumber() string
	GetPhoneNumberVerified() bool
	GetRule(key string) []string
	GetRules() map[string][]string
	CheckRule(key string, value string) bool
}

type sClaims struct {
	Email               string              `json:"email,omitempty"`
	EmailVerified       *bool               `json:"email_verified,omitempty"`
	PhoneNumber         string              `json:"phone_number,omitempty"`
	PhoneNumberVerified *bool               `json:"phone_number_verified,omitempty"`
	Rules               map[string][]string `json:"rules,omitempty"`
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

func (r *sJwtClient) GetRule(key string) []string {
	return r.claims.Rules[key]
}

func (r *sJwtClient) GetRules() map[string][]string {
	return r.claims.Rules
}

func (r *sJwtClient) CheckRule(key string, value string) bool {
	v, ok := r.claims.Rules[key]
	if !ok {
		return false
	}
	if !slices.Contains(v, value) {
		return false
	}
	return true
}
