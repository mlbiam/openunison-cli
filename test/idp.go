package oulogintest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type OIDCMock struct {
	privateKey *ecdsa.PrivateKey
	Issuer     string
	Server     *httptest.Server
}

func StartTestOIDCProvider() (*OIDCMock, error) {
	// Generate signing key for JWT
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing key: %w", err)
	}

	mock := &OIDCMock{
		privateKey: privKey,
	}

	// Handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", mock.discoveryHandler)
	mux.HandleFunc("/authorize", mock.authorizeHandler)
	mux.HandleFunc("/token", mock.tokenHandler)

	// Self-signed cert
	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, fmt.Errorf("failed to create cert: %w", err)
	}

	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	server.StartTLS()

	mock.Issuer = server.URL
	mock.Server = server

	return mock, nil
}

func (m *OIDCMock) Close() {
	if m.Server != nil {
		m.Server.Close()
	}
}

func (m *OIDCMock) discoveryHandler(w http.ResponseWriter, r *http.Request) {
	resp := map[string]string{
		"issuer":                 m.Issuer,
		"authorization_endpoint": m.Issuer + "/authorize",
		"token_endpoint":         m.Issuer + "/token",
		"jwks_uri":               m.Issuer + "/keys", // stub
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (m *OIDCMock) authorizeHandler(w http.ResponseWriter, r *http.Request) {
	idToken, err := m.generateIDToken("testuser")
	if err != nil {
		http.Error(w, "could not generate id_token", http.StatusInternalServerError)
		return
	}

	refreshToken := "dummy-refresh-token"
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = m.Issuer + "/callback"
	}

	http.Redirect(w, r,
		fmt.Sprintf("%s?id_token=%s&refresh_token=%s", redirectURI, idToken, refreshToken),
		http.StatusFound,
	)
}

func (m *OIDCMock) tokenHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "dummy-refresh-token" {
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}

	idToken, err := m.generateIDToken("testuser")
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}

	resp := map[string]string{
		"id_token":      idToken,
		"access_token":  idToken,
		"refresh_token": "dummy-refresh-token",
		"token_type":    "Bearer",
		"expires_in":    "3600",
	}
	w.Header().Set("Content-Type", "application/json")

	jsonBytes, err := json.Marshal(resp)
	if err != nil {
		panic(err)
	}

	jsonString := string(jsonBytes)

	fmt.Printf(jsonString)
	w.Write(([]byte(jsonString)))

	//json.NewEncoder(w).Encode(resp)
}

func (m *OIDCMock) generateIDToken(sub string) (string, error) {
	claims := jwt.MapClaims{
		"iss": m.Issuer,
		"sub": sub,
		"aud": "my-client-id",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return token.SignedString(m.privateKey)
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"127.0.0.1"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}
