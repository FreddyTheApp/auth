package services

import (
	"crypto/rand"
	"encoding/base64"
)

func generateEmailVerificationToken() (string, error) {
	b := make([]byte, 32) // generating a 256 bit token
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil
}
