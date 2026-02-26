package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testUserId = "123"

func generateTestKeyFiles(t *testing.T) (string, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	pubBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	pubPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubBytes,
	})

	tmpDir := t.TempDir()

	privatePath := filepath.Join(tmpDir, "private.pem")
	publicPath := filepath.Join(tmpDir, "public.pem")

	if err := os.WriteFile(privatePath, privPem, 0600); err != nil {
		t.Fatalf("failed to write private key: %v", err)
	}

	if err := os.WriteFile(publicPath, pubPem, 0644); err != nil {
		t.Fatalf("failed to write public key: %v", err)
	}

	return privatePath, publicPath
}

func testRSAConfig(private, public string) Config {
	return Config{
		Algorithm:      RS256,
		PrivateKeyPath: private,
		PublicKeyPath:  public,
		Issuer:         "test-issuer",
		Audience:       "test-audience",
		AccessTTL:      time.Minute,
		RefreshTTL:     time.Hour,
	}
}

func TestRS256_GenerateAndVerifyAccess(t *testing.T) {
	privateKey, publicKey := generateTestKeyFiles(t)

	cfg := testRSAConfig(privateKey, publicKey)
	svc, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	bundle, err := svc.GenerateTokenPair(testUserId)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	claims, err := svc.VerifyAccessToken(bundle.AccessToken)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	if claims.Subject != testUserId {
		t.Fatalf("expected subject %s, got %s", testUserId, claims.Subject)
	}
}

func TestRS256_InvalidSignature(t *testing.T) {
	privateKey, _ := generateTestKeyFiles(t)
	_, wrongPublicKey := generateTestKeyFiles(t)

	cfg := testRSAConfig(privateKey, wrongPublicKey)
	svc, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	bundle, err := svc.GenerateTokenPair(testUserId)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	_, err = svc.VerifyAccessToken(bundle.AccessToken)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

func TestRS256_ExpiredToken(t *testing.T) {
	privateKey, publicKey := generateTestKeyFiles(t)

	cfg := Config{
		Algorithm:      RS256,
		PrivateKeyPath: privateKey,
		PublicKeyPath:  publicKey,
		Issuer:         "test-issuer",
		AccessTTL:      -time.Minute,
	}
	svc, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	bundle, err := svc.GenerateTokenPair(testUserId)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	_, err = svc.VerifyAccessToken(bundle.AccessToken)
	if err == nil {
		t.Fatal("expected expired token error")
	}
}
