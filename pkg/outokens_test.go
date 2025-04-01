package outokens

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	oulogintest "github.com/tremolosecurity/kubectl-login/test"
)

func createTestJWT(expiration time.Time) string {
	claims := jwt.MapClaims{
		"exp": expiration.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, _ := token.SignedString([]byte("test-secret")) // Signature doesn't matter for ParseUnverified
	return signedToken
}

func getPEMFromTLSCertificate(cert tls.Certificate) (certPEM, keyPEM []byte, err error) {
	// Encode certificate
	for _, certDER := range cert.Certificate {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		}
		certPEM = append(certPEM, pem.EncodeToMemory(block)...)
	}

	// Encode private key
	switch key := cert.PrivateKey.(type) {
	case *x509.Certificate:
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: key.Raw,
		})
	case interface{}:
		keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to marshal private key: %w", err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		})
	}

	return certPEM, keyPEM, nil
}

func TestIdentityProvider(t *testing.T) {
	idp, err := oulogintest.StartTestOIDCProvider()

	if err != nil {
		t.Fatalf("could not start idp %v", err)
	}

	pem, _, err := getPEMFromTLSCertificate(idp.Server.TLS.Certificates[0])

	session, err := NewOidcSession(idp.Issuer, "", string(pem), "", "")

	if err != nil {
		t.Fatalf("could init session %v", err)
	}

	if session.AuthUrl == "" {
		t.Error("No authorization url")
	}

	if session.TokenUrl == "" {
		t.Error("No token url")
	}

	idp.Close()
}

func TestIsTokenNeedsRefresh(t *testing.T) {
	tests := []struct {
		name        string
		expiryDelta time.Duration
		expect      bool
	}{
		{
			name:        "Expired token",
			expiryDelta: -10 * time.Second,
			expect:      true,
		},
		{
			name:        "Valid token (expires in 1 hour)",
			expiryDelta: 1 * time.Hour,
			expect:      false,
		},
		{
			name:        "Token expiring in 19 seconds, should be renewed",
			expiryDelta: 19 * time.Second,
			expect:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := createTestJWT(time.Now().Add(tc.expiryDelta))
			session := OidcSession{IDToken: token}
			needsRefresh, err := session.isTokenNeedsRefresh()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if needsRefresh != tc.expect {
				t.Errorf("expected %v, got %v", tc.expect, needsRefresh)
			}
		})
	}
}

func TestSaveAndLoadSession(t *testing.T) {
	var err error
	session := &OidcSession{
		IDToken:      "test-id-token",
		RefreshToken: "test-refresh-token",
		Issuer:       "https://example.com",
		TokenUrl:     "https://example.com/token",
		AuthUrl:      "https://example.com/auth",
		ClientID:     "test-client-id",
		CaCert:       "-----BEGIN CERTIFICATE-----\nMIIBUjCB+qADAgECAgEBMAoGCCqGSM49BAMCMBQxEjAQBgNVBAMTCTEyNy4wLjAu\nMTAeFw0yNTAzMjkxNTEwNDRaFw0yNjAzMjkxNTEwNDRaMBQxEjAQBgNVBAMTCTEy\nNy4wLjAuMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABM2UBD7TWZmxI+Xv/ltU\nNjBbX2ibLd5rB4Jxv/n4R5kI4rPtlNMqUxxf60JEI68H+79djQ8DPRgjyHf4EweZ\nnqyjPTA7MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAUBgNV\nHREEDTALggkxMjcuMC4wLjEwCgYIKoZIzj0EAwIDRwAwRAIgU0iGZJtnPXWzAr0W\nAc2Sa9oidWH4yHdiUfqAv5ocO20CIE3J33TtlpBHPuRCnCqtNzog9GjkDV+R4SfV\nbci8jEiv\n-----END CERTIFICATE-----",
	}

	session.TLSConfig, err = createTLSConfig(session.CaCert)
	if err != nil {
		t.Fatalf("failed to create TLS config: %v", err)
	}

	filePath, err := SaveSessionToTempFile(session)
	if err != nil {
		t.Fatalf("failed to save session: %v", err)
	}
	defer os.Remove(filePath)

	loadedSession, err := LoadSessionFromFile(filePath)
	if err != nil {
		t.Fatalf("failed to load session: %v", err)
	}

	if loadedSession.IDToken != session.IDToken {
		t.Errorf("IDToken mismatch: expected %s, got %s", session.IDToken, loadedSession.IDToken)
	}
	if loadedSession.RefreshToken != session.RefreshToken {
		t.Errorf("RefreshToken mismatch: expected %s, got %s", session.RefreshToken, loadedSession.RefreshToken)
	}
	if loadedSession.Issuer != session.Issuer {
		t.Errorf("Issuer mismatch: expected %s, got %s", session.Issuer, loadedSession.Issuer)
	}
	if loadedSession.TokenUrl != session.TokenUrl {
		t.Errorf("TokenUrl mismatch: expected %s, got %s", session.TokenUrl, loadedSession.TokenUrl)
	}
	if loadedSession.AuthUrl != session.AuthUrl {
		t.Errorf("AuthUrl mismatch: expected %s, got %s", session.AuthUrl, loadedSession.AuthUrl)
	}
	if loadedSession.ClientID != session.ClientID {
		t.Errorf("ClientID mismatch: expected %s, got %s", session.ClientID, loadedSession.ClientID)
	}
	if loadedSession.CaCert != session.CaCert {
		t.Errorf("CaCert mismatch")
	}

	if loadedSession.TLSConfig == nil {
		t.Errorf("TLSConfig should not be nil")
	} else if session.TLSConfig == nil {
		t.Errorf("Expected TLSConfig to be initialized in original session")
	} else {
		if len(loadedSession.TLSConfig.RootCAs.Subjects()) != len(session.TLSConfig.RootCAs.Subjects()) {
			t.Errorf("TLSConfig RootCAs mismatch in number of subjects")
		}
		if loadedSession.TLSConfig.InsecureSkipVerify != session.TLSConfig.InsecureSkipVerify {
			t.Errorf("TLSConfig InsecureSkipVerify mismatch")
		}
	}
}

func TestRefreshSession_Success(t *testing.T) {
	idp, err := oulogintest.StartTestOIDCProvider()
	if err != nil {
		t.Fatalf("could not start idp: %v", err)
	}
	defer idp.Close()

	cert := idp.Server.TLS.Certificates[0]
	pem, _, err := getPEMFromTLSCertificate(cert)
	if err != nil {
		t.Fatalf("failed to extract cert: %v", err)
	}

	session, err := NewOidcSession(idp.Issuer, "test-client", string(pem), "", "dummy-refresh-token")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	tok := session.RefreshSession(context.Background())
	if !tok || err != nil {
		t.Errorf("expected successful refresh, got error: %v", err)
	}

	if session.IDToken == "" {
		t.Error("expected ID token to be updated")
	}
}

func TestRefreshSession_Failure(t *testing.T) {
	session := &OidcSession{
		ClientID:     "bad-client",
		TokenUrl:     "https://invalid/token",
		RefreshToken: "invalid-token",
	}

	ok := session.RefreshSession(context.Background())
	if ok {
		t.Errorf("expected refresh to fail, but got success")
	}
}
