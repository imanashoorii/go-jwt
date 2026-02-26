package go_jwt

import (
	"testing"
	"time"
)

func testConfig() Config {
	return Config{
		Algorithm:  HS256,
		Secret:     "supersecret",
		Issuer:     "test-issuer",
		Audience:   "test-audience",
		AccessTTL:  time.Minute,
		RefreshTTL: time.Hour,
	}
}

func TestHS256_GenerateAndVerifyAccess(t *testing.T) {
	cfg := testConfig()
	svc, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	bundle, err := svc.GenerateTokenPair("123")
	if err != nil {
		t.Fatal(err)
	}

	claims, err := svc.VerifyAccessToken(bundle.AccessToken)
	if err != nil {
		t.Fatal(err)
	}

	if claims.Subject != "123" {
		t.Fatalf("expected subject 123, got %s", claims.Subject)
	}

	if claims.TokenType != ACCESS {
		t.Fatalf("expected access token")
	}
}

func TestHS256_Refresh(t *testing.T) {
	cfg := testConfig()
	svc, _ := New(cfg)

	bundle, _ := svc.GenerateTokenPair("999")

	newBundle, err := svc.Refresh(bundle.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}

	if newBundle.AccessToken == "" {
		t.Fatal("new access token empty")
	}
}

func TestHS256_ExpiredToken(t *testing.T) {
	cfg := testConfig()
	cfg.AccessTTL = -1 * time.Minute

	svc, _ := New(cfg)

	bundle, _ := svc.GenerateTokenPair("123")

	_, err := svc.VerifyAccessToken(bundle.AccessToken)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestHS256_WrongSecret(t *testing.T) {
	cfg := testConfig()
	svc1, _ := New(cfg)

	bundle, _ := svc1.GenerateTokenPair("123")

	cfg.Secret = "wrongsecret"
	svc2, _ := New(cfg)

	_, err := svc2.VerifyAccessToken(bundle.AccessToken)
	if err == nil {
		t.Fatal("expected error with wrong secret")
	}
}

func TestHS256_InvalidTokenType(t *testing.T) {
	cfg := testConfig()
	svc, _ := New(cfg)

	bundle, _ := svc.GenerateTokenPair("123")

	_, err := svc.VerifyAccessToken(bundle.RefreshToken)
	if err == nil {
		t.Fatal("expected invalid token type error")
	}
}
