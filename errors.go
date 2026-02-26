package go_jwt

import "errors"

var (
	ErrInvalidToken       = errors.New("invalid token")
	ErrExpiredToken       = errors.New("token expired")
	ErrInvalidTokenType   = errors.New("invalid token type")
	ErrBlacklisted        = errors.New("token blacklisted")
	ErrInvalidSigningAlgo = errors.New("invalid signing algorithm")
)
