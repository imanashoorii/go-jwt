package core

import "github.com/imanashoorii/go-jwt/core/internal"

type Service struct {
	cfg       Config
	signKey   interface{}
	verifyKey interface{}
}

func New(cfg Config) (*Service, error) {
	s := &Service{
		cfg: cfg,
	}

	switch cfg.Algorithm {
	case HS256:
		s.signKey = []byte(cfg.Secret)
		s.verifyKey = []byte(cfg.Secret)

	case RS256:
		privateKey, err := internal.LoadPrivateKey(cfg.PrivateKeyPath)
		if err != nil {
			return nil, err
		}
		publicKey, err := internal.LoadPublicKey(cfg.PublicKeyPath)
		if err != nil {
			return nil, err
		}
		s.signKey = privateKey
		s.verifyKey = publicKey

	default:
		return nil, ErrInvalidSigningAlgo
	}

	return s, nil
}
