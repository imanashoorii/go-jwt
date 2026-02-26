package go_jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func (s *Service) signingMethod() jwt.SigningMethod {
	switch s.cfg.Algorithm {
	case HS256:
		return jwt.SigningMethodHS256
	case RS256:
		return jwt.SigningMethodRS256
	default:
		return jwt.SigningMethodHS256
	}
}

func (s *Service) verify(tokenStr string) (*Claims, error) {

	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		return s.verifyKey, nil
	})
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}

	if claims.Issuer != s.cfg.Issuer {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

func (s *Service) GenerateTokenPair(userID string) (*TokenBundle, error) {

	now := time.Now()

	accessJTI := uuid.NewString()
	refreshJTI := uuid.NewString()

	accessExp := now.Add(s.cfg.AccessTTL)
	refreshExp := now.Add(s.cfg.RefreshTTL)

	accessClaims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ID:        accessJTI,
			Issuer:    s.cfg.Issuer,
			Audience:  []string{s.cfg.Audience},
			ExpiresAt: jwt.NewNumericDate(accessExp),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		TokenType: ACCESS,
	}

	refreshClaims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ID:        refreshJTI,
			Issuer:    s.cfg.Issuer,
			Audience:  []string{s.cfg.Audience},
			ExpiresAt: jwt.NewNumericDate(refreshExp),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		TokenType: REFRESH,
	}

	accessToken, err := jwt.NewWithClaims(s.signingMethod(), accessClaims).SignedString(s.signKey)
	if err != nil {
		return nil, err
	}

	refreshToken, err := jwt.NewWithClaims(s.signingMethod(), refreshClaims).SignedString(s.signKey)
	if err != nil {
		return nil, err
	}

	return &TokenBundle{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    accessExp.Unix(),
	}, nil
}

func (s *Service) VerifyAccessToken(access string) (*Claims, error) {
	claims, err := s.verify(access)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != ACCESS {
		return nil, ErrInvalidTokenType
	}

	return claims, nil
}

func (s *Service) Refresh(refresh string) (*TokenBundle, error) {

	claims, err := s.verify(refresh)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != REFRESH {
		return nil, ErrInvalidTokenType
	}

	return s.GenerateTokenPair(claims.Subject)
}
