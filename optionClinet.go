package jwt

type OptionClient interface {
	apply(_jwt *sJwtClient)
}

type optionClientFunc func(*sJwtClient)

func (f optionClientFunc) apply(_jwt *sJwtClient) {
	f(_jwt)
}

func WithExpectedIssuer(expectedIssuer string) OptionClient {
	return optionClientFunc(func(_jwt *sJwtClient) {
		_jwt.expectedIssuer = expectedIssuer
	})
}
