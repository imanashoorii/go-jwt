package core

import (
	"time"
)

type Algorithm string

const (
	HS256 Algorithm = "HS256"
	RS256 Algorithm = "RS256"
)

const (
	ACCESS  string = "access"
	REFRESH string = "refresh"
)

type Config struct {
	Algorithm  Algorithm     `mapstructure:"algorithm"`
	Issuer     string        `mapstructure:"issuer"`
	Audience   string        `mapstructure:"audience"`
	AccessTTL  time.Duration `mapstructure:"access_ttl"`
	RefreshTTL time.Duration `mapstructure:"refresh_ttl"`

	// HS256
	Secret string `mapstructure:"secret"`

	// RS256
	PrivateKeyPath string `mapstructure:"private_key_path"`
	PublicKeyPath  string `mapstructure:"public_key_path"`
}
