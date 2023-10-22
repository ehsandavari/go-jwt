package main

import (
	"github.com/ehsandavari/go-jwt"
	"github.com/google/uuid"
	"time"
)

func main() {
	_jwtServer := jwt.NewJwtServer(
		"RS512",
		"-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCOVSFfbrSphqpMkOp+vCWkSYiu\nIFUONM366m2N0WuUeRANwimipKydERSiyu//u1zizvN5kQZ+ANK5oxFaZrOqvP5/\nSn/EKNqx+ydRNXN5EgbkjD8tcAciMM/Ivd37IlZH2yAmAQzUWtk/uBb5piuGS90i\ngTyoKeICImSjjhoClQIDAQAB\n-----END PUBLIC KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQCOVSFfbrSphqpMkOp+vCWkSYiuIFUONM366m2N0WuUeRANwimi\npKydERSiyu//u1zizvN5kQZ+ANK5oxFaZrOqvP5/Sn/EKNqx+ydRNXN5EgbkjD8t\ncAciMM/Ivd37IlZH2yAmAQzUWtk/uBb5piuGS90igTyoKeICImSjjhoClQIDAQAB\nAoGAd2YAre7PjRrTx5EVtaUdqpipGPE0iMtRM7jumDZimdWI2xHTHYYo60XF2t6E\nwDGrtPRImOVI3fDQ1TtvNjfLZR/2GqT65Z8sGA2G8r9h/IRiosAjDV2H0Al2dU6s\np2WNiM7Lmo9nRFbkv3owYm0n5sxUM6WahX2Mlncsp6JAHK0CQQDV+yPHHQGl6Uiz\nq/UGjhJ8AdhXAsVxRHLLO4cHumG43Rt7Eek4SsS/pgE/xOIojo78ODNmA1dMl2FO\nfpI9+DIfAkEAqkg10Fm1ngpcFG/5Q4aNl3ssRz0nUYPNHP3NRBVGi0oCvW9cZHeh\n/d2+kzebf+442aTjNu3iia3eCdbFnhU8ywJBAM4kQzNvHkdXllKBNmw6MlSE8oXg\nhZW4+14O2ub3B22wlOjbOHKilSiMJGfqpHWt4NHa0qlUTqXasEOObBSHJsECQGgs\nBufwicAmfFBwdCCQRzzduKfYTJ58sFXFGvdEwMRjwatcXjyER5DEQFtV0IaCGTtk\nuTAYdddei5CfWIQuX+MCQQC0/CySPoXLzR3vFg8XWTTEK5lokonlob4ZfRnSBJNu\nX0WtFj7MAWmFRAmXRG2yiCMMSA0/3xZ14CBwwoKHwx/4\n-----END RSA PRIVATE KEY-----",
		jwt.WithIssuer("WithIssuer"),
		jwt.WithAudience("api1", "api2"),
		jwt.WithExpiresAt(time.Now().Add(8766*time.Hour)),
		jwt.WithNotBefore(time.Now()),
		jwt.WithIssuedAt(time.Now()),
		jwt.WithID("asdlmksfkdfmaksdfmaskld"),
	)
	token, err := _jwtServer.GenerateToken(
		uuid.New().String(),
		jwt.WithEmail("ehsandavari.ir@gmail.com", false),
		jwt.WithPhoneNumber("09215580690", true),
	)
	if err != nil {
		panic(err)
	}
	println(token)

	token, err = _jwtServer.GenerateToken(
		uuid.New().String(),
		jwt.WithEmail("", false),
		jwt.WithPhoneNumber("09215580690", true),
		jwt.WithRules(map[string][]string{
			"test-service": {
				"create",
				"read",
				"update",
				"delete",
			},
		}),
	)
	if err != nil {
		panic(err)
	}
	println(token)

	// verify
	verifyToken, err := _jwtServer.VerifyToken(token, "api1", "WithIssuer")
	if err != nil {
		panic(err)
	}
	println(verifyToken)
	println(_jwtServer.GetUserId())

	_jwtClient := jwt.NewJwtClient(
		"-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCOVSFfbrSphqpMkOp+vCWkSYiu\nIFUONM366m2N0WuUeRANwimipKydERSiyu//u1zizvN5kQZ+ANK5oxFaZrOqvP5/\nSn/EKNqx+ydRNXN5EgbkjD8tcAciMM/Ivd37IlZH2yAmAQzUWtk/uBb5piuGS90i\ngTyoKeICImSjjhoClQIDAQAB\n-----END PUBLIC KEY-----",
	)
	verifyToken, err = _jwtClient.VerifyToken(token, "api1", "WithIssuer")
	if err != nil {
		panic(err)
	}
	println(verifyToken)
	println(_jwtClient.CheckRule("test-service1", "update1"))
	println(_jwtClient.CheckRule("test-service1", "update"))
	println(_jwtClient.CheckRule("test-service", "update1"))
	println(_jwtClient.CheckRule("test-service", "update"))
	println(_jwtClient.CheckRule("test-service", "delete"))
	println(_jwtClient.GetEmail())
}
