package outokens

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	flock "github.com/gofrs/flock"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/browser"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

var logger *zap.Logger

func SetLogger(debug bool) {
	if debug {
		logger = zap.Must(zap.NewDevelopment())
	} else {
		logger = zap.Must(zap.NewProduction())
	}
}

type OidcSession struct {
	IDToken      string      `json:"id_token"`
	RefreshToken string      `json:"refresh_token"`
	Issuer       string      `json:"issuer"`
	TokenUrl     string      `json:"token_url"`
	AuthUrl      string      `json:"auth_url"`
	ClientID     string      `json:"client_id"`
	CaCert       string      `json:"ca_cert"`
	TLSConfig    *tls.Config `json:"-"`
}

type OIDCDiscoveryDoc struct {
	TokenEndpoint string `json:"token_endpoint"`
	AzEndpoint    string `json:"authorization_endpoint"`
}

func NewOidcSession(issuer string, clientID string, caCert string, idToken string, refreshToken string) (*OidcSession, error) {
	var err error
	session := &OidcSession{
		Issuer:       issuer,
		ClientID:     clientID,
		IDToken:      idToken,
		RefreshToken: refreshToken,
	}

	session.TLSConfig, err = createTLSConfig(caCert)

	if err != nil {
		return nil, err
	}

	err = session.loadUrlsFromIssuer(context.Background())

	if err != nil {
		return nil, err
	} else {
		return session, nil
	}

}

func createTLSConfig(caCert string) (*tls.Config, error) {
	if caCert != "" {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM([]byte(caCert)) {
			return nil, fmt.Errorf("failed to append CA certificate")
		}
		return &tls.Config{
			RootCAs:            caCertPool,
			InsecureSkipVerify: true,
		}, nil
	}
	return &tls.Config{}, nil
}

func (session *OidcSession) isTokenNeedsRefresh() (bool, error) {

	token, _, err := jwt.NewParser().ParseUnverified(session.IDToken, jwt.MapClaims{})
	if err != nil {
		return false, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false, errors.New("invalid claims")
	}

	expRaw, ok := claims["exp"]
	if !ok {
		return false, errors.New("missing exp claim")
	}

	expFloat, ok := expRaw.(float64)
	if !ok {
		return false, errors.New("invalid exp claim type")
	}

	expTime := time.Unix(int64(expFloat), 0)
	now := time.Now()
	if expTime.Before(now.Add(20 * time.Second)) {
		return true, nil
	}

	return false, nil
}

func (session *OidcSession) loadUrlsFromIssuer(ctx context.Context) error {
	// Make sure issuer doesn't end with a slash
	issuer := strings.TrimSuffix(session.Issuer, "/")

	discoveryURL := issuer + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second,

		Transport: &http.Transport{
			TLSClientConfig: session.TLSConfig,
		}}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery request failed with status: %s", resp.Status)
	}

	logger.Debug("Content-Type", zap.String("content_type", resp.Header["Content-Type"][0]))

	var doc OIDCDiscoveryDoc

	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("failed to decode discovery document: %w", err)
	}

	if doc.TokenEndpoint == "" {
		return fmt.Errorf("token_endpoint not found in discovery document")
	}

	if doc.AzEndpoint == "" {
		return fmt.Errorf("authorization_endpoint not found in discovery document")
	}

	session.AuthUrl = doc.AzEndpoint
	session.TokenUrl = doc.TokenEndpoint

	return nil
}

func (session *OidcSession) refreshIdToken(ctx context.Context) (*oauth2.Token, error) {
	config := &oauth2.Config{
		ClientID: session.ClientID,
		Endpoint: oauth2.Endpoint{
			TokenURL: session.TokenUrl,
		},
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: session.TLSConfig,
		},
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	tokenSource := config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: session.RefreshToken,
	})

	token, err := tokenSource.Token()
	if err != nil {
		// Check if the error is an *oauth2.RetrieveError to inspect the status code
		var retrieveErr *oauth2.RetrieveError
		if errors.As(err, &retrieveErr) {
			if retrieveErr.Response != nil && retrieveErr.Response.StatusCode == http.StatusUnauthorized {
				return nil, fmt.Errorf("refresh token rejected with 401: %w", err)
			}
		}
		return nil, err
	}

	return token, nil
}

func SaveSessionToTempFile(session *OidcSession, customPath ...string) (string, error) {
	var path string
	if len(customPath) > 0 && customPath[0] != "" {
		path = customPath[0]
	} else {
		tempFile, err := os.CreateTemp("", "oidc-session-*.json")
		if err != nil {
			return "", err
		}
		defer tempFile.Close()
		path = tempFile.Name()
	}

	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", err
	}

	return path, nil
}

func LoadSessionFromFile(filePath string) (*OidcSession, error) {
	lock := flock.New(filePath + ".lock")
	locked, err := lock.TryLock()
	if err != nil {
		return nil, fmt.Errorf("failed to acquire file lock: %w", err)
	}
	if !locked {
		return nil, fmt.Errorf("could not acquire file lock")
	}
	defer lock.Unlock()

	f, err := os.OpenFile(filePath, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var session OidcSession
	decoder := json.NewDecoder(f)
	err = decoder.Decode(&session)
	if err != nil {
		return nil, err
	}

	session.TLSConfig, err = createTLSConfig(session.CaCert)
	if err != nil {
		return nil, err
	}

	return &session, nil
}

func (session *OidcSession) RefreshSession(ctx context.Context) bool {
	needsRefresh, err := session.isTokenNeedsRefresh()
	if err != nil {
		logger.Debug("failed to check token expiration", zap.Error(err))
		return false
	}
	if !needsRefresh {
		return false
	}

	token, err := session.refreshIdToken(ctx)
	if err != nil {
		var retrieveErr *oauth2.RetrieveError
		if errors.As(err, &retrieveErr) {
			if retrieveErr.Response != nil && retrieveErr.Response.StatusCode == http.StatusUnauthorized {
				logger.Debug("refresh failed with 401 - unauthorized, reauthenticating")
				err = session.handle401WithAuthCodeFlow(ctx)
				if err != nil {
					logger.Debug("failed to reauthenticate", zap.Error(err))
					return false
				}
				logger.Debug("Reauthentication successful")
				return true
			}
		}
		return false
	}
	session.IDToken = token.AccessToken
	if token.RefreshToken != "" {
		session.RefreshToken = token.RefreshToken
	}
	return true
}

func (session *OidcSession) handle401WithAuthCodeFlow(ctx context.Context) error {
	// Start the redirect server
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	srv := &http.Server{Addr: ":8000"}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Missing code", http.StatusBadRequest)
			errCh <- fmt.Errorf("missing code in callback")
			return
		}
		u, err := url.Parse(session.Issuer)
		if err != nil {
			http.Error(w, "Invalid issuer", http.StatusInternalServerError)
			errCh <- fmt.Errorf("invalid issuer format: %w", err)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("https://%s/auth/forms/cli-login-finished.jsp", u.Host), http.StatusSeeOther)
		codeCh <- code
		go srv.Shutdown(context.Background())
	})

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Generate nonce and PKCE
	nonce := randomString(32)
	codeVerifier := randomString(64)
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	// Build the auth URL
	authUrl, err := url.Parse(session.AuthUrl)
	if err != nil {
		return err
	}

	q := authUrl.Query()
	q.Set("response_type", "code")
	q.Set("client_id", session.ClientID)
	q.Set("redirect_uri", "http://localhost:8000")
	q.Set("scope", "openid profile email")
	q.Set("state", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	authUrl.RawQuery = q.Encode()

	// Launch browser
	logger.Debug("Opening browser for authentication", zap.String("url", authUrl.String()))
	openBrowser(authUrl.String())

	select {
	case code := <-codeCh:
		// Exchange code for token
		token, err := session.ExchangeCodeForToken(ctx, code, "http://localhost:8000/", codeVerifier)
		if err != nil {
			return err
		}
		session.IDToken = token.Extra("id_token").(string)
		session.RefreshToken = token.RefreshToken
		return nil
	case err := <-errCh:
		return err
	case <-time.After(1 * time.Minute):
		return fmt.Errorf("authentication timed out")
	}
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

func openBrowser(url string) {

	if err := browser.OpenURL(url); err != nil {
		logger.Debug("failed to open browser", zap.Error(err))
	}
}

func (session *OidcSession) ExchangeCodeForToken(ctx context.Context, code string, redirectURI, codeVerifier string) (*oauth2.Token, error) {
	config := &oauth2.Config{
		ClientID:    session.ClientID,
		RedirectURL: redirectURI,
		Endpoint: oauth2.Endpoint{
			TokenURL: session.TokenUrl,
		},
		Scopes: []string{"openid", "profile", "email"},
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: session.TLSConfig,
		},
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	token, err := config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return nil, err
	}

	return token, nil
}
