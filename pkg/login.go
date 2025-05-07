package outokens

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

type oidcState struct {
	nonce         string
	codeVerifier  string
	codeChallenge string
}

type OpenUnisonToken struct {
	Token    OpenUnisonSession `json:"token"`
	UserName string            `json:"displayName"`
}

type OpenUnisonSession struct {
	UserName     string
	K8sURL       string `json:"kubectl Windows Command"`
	CtxName      string `json:"kubectl Command"`
	OuCert       string `json:"OpenUnison Server CA Certificate"`
	K8sCert      string `json:"Kubernetes API Server CA Certificate"`
	IdToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`

	PathToConfig string

	OidcSession *OidcSession
}

var ShowLogs bool

func LoginToOpenUnison(openUnisonHost string, caCert string, ctx context.Context) (*OpenUnisonSession, error) {
	// Start the redirect server
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	srv := &http.Server{Addr: "127.0.0.1:8400"}

	// Build the auth URL
	issuer := "https://" + openUnisonHost + "/auth/idp/k8s-login-cli"

	oidcState := &oidcState{}

	session, err := NewOidcSession(issuer, "cli-local", string(caCert), "", "")

	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC session: %w", err)
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Generate nonce and PKCE
		oidcState.nonce = randomString(32)
		oidcState.codeVerifier = randomString(64)
		h := sha256.New()
		h.Write([]byte(oidcState.codeVerifier))
		oidcState.codeChallenge = base64.RawURLEncoding.EncodeToString(h.Sum(nil))

		authUrl, err := url.Parse(issuer + "/auth")
		if err != nil {
			panic(err)
		}

		q := authUrl.Query()
		q.Set("response_type", "code")
		q.Set("client_id", "cli-local")
		q.Set("redirect_uri", "http://127.0.0.1:8400/redirect")
		q.Set("scope", "openid profile email")
		q.Set("state", oidcState.nonce)
		q.Set("code_challenge", oidcState.codeChallenge)
		q.Set("code_challenge_method", "S256")
		authUrl.RawQuery = q.Encode()

		http.Redirect(w, r, authUrl.String(), http.StatusSeeOther)
	})

	http.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Missing code", http.StatusBadRequest)
			errCh <- fmt.Errorf("missing code in callback")
			return
		}

		state := r.URL.Query().Get("state")
		if state != oidcState.nonce {
			http.Error(w, "Invalid state", http.StatusBadRequest)
			errCh <- fmt.Errorf("invalid state in callback")
			return
		}

		http.Redirect(w, r, fmt.Sprintf("https://%s/auth/forms/cli-login-finished.jsp", openUnisonHost), http.StatusSeeOther)
		codeCh <- code
		go srv.Shutdown(context.Background())
	})

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Build the auth URL
	authUrl, err := url.Parse("https://" + openUnisonHost + "/cli-login")
	if err != nil {
		return nil, err
	}

	// Launch browser
	if ShowLogs {
		fmt.Printf("Opening browser for authentication to %s", authUrl.String())
	}
	openBrowser(authUrl.String())

	select {
	case code := <-codeCh:
		// Exchange code for token
		token, err := session.ExchangeCodeForToken(ctx, code, "http://127.0.0.1:8400/redirect", oidcState.codeVerifier)
		if err != nil {
			return nil, err
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			return nil, fmt.Errorf("No id_token")
		}

		loadJsonUrl := "https://" + openUnisonHost + "/k8slogin/token/user"

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, loadJsonUrl, nil)
		req.Header.Add("Authorization", "Bearer "+rawIDToken)

		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		client := &http.Client{Timeout: 10 * time.Second,

			Transport: &http.Transport{
				TLSClientConfig: session.TLSConfig,
			}}

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch discovery document: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("discovery request failed with status: %s", resp.Status)
		}

		var ouToken OpenUnisonToken
		if err := json.NewDecoder(resp.Body).Decode(&ouToken); err != nil {
			return nil, fmt.Errorf("failed to load the authenticated session: %w", err)
		}

		ouSession := ouToken.Token
		ouSession.UserName = ouToken.UserName

		ouSession.OidcSession, err = NewOidcSession("https://"+openUnisonHost+"/auth/idp/k8sIdp", "kubernetes", session.CaCert, ouSession.IdToken, ouSession.RefreshToken)

		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC session: %w", err)
		}

		return &ouSession, nil
	case err := <-errCh:
		return nil, err
	case <-time.After(1 * time.Minute):
		return nil, fmt.Errorf("authentication timed out")
	}
}

func (session *OpenUnisonSession) SaveKubectlConfigFromSession(execCommandPath string, sessionFilePath string, debug bool, contextNameOverride string, forceBeta bool) error {
	clusterName := session.CtxName
	userName := session.UserName
	contextName := userName + "@" + clusterName
	userAndContext := contextName

	if contextNameOverride != "" {
		contextName = contextNameOverride
	}

	pathOptions := clientcmd.NewDefaultPathOptions()
	config, err := pathOptions.GetStartingConfig()
	if err != nil {
		return fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	if config.Clusters[clusterName] == nil {
		config.Clusters[clusterName] = &api.Cluster{
			Server:                   session.K8sURL,
			CertificateAuthorityData: []byte(session.K8sCert),
		}
	}

	parsedURL, err := url.Parse(session.OidcSession.Issuer)
	if err != nil {
		return err
	}

	host := parsedURL.Hostname()

	execArgs := []string{"oidc", "--openunison-host", host}
	if debug {
		execArgs = append(execArgs, "--debug")
	}

	if session.OidcSession.CaCert != "" {
		execArgs = append(execArgs, "--cacert-path", session.OidcSession.CaCert)
	}

	if forceBeta {
		execArgs = append(execArgs, "--auth-beta")
	}

	execArgs = append(execArgs, sessionFilePath)

	if forceBeta {
		config.AuthInfos[userAndContext] = &api.AuthInfo{
			Exec: &api.ExecConfig{
				APIVersion:         "client.authentication.k8s.io/v1beta1",
				Command:            execCommandPath,
				Args:               execArgs,
				Env:                []api.ExecEnvVar{},
				InstallHint:        "copy shell file",
				ProvideClusterInfo: false,
				InteractiveMode:    api.NeverExecInteractiveMode,
			},
		}
	} else {
		config.AuthInfos[userAndContext] = &api.AuthInfo{
			Exec: &api.ExecConfig{
				APIVersion:         "client.authentication.k8s.io/v1",
				Command:            execCommandPath,
				Args:               execArgs,
				Env:                []api.ExecEnvVar{},
				InstallHint:        "copy shell file",
				ProvideClusterInfo: false,
				InteractiveMode:    api.NeverExecInteractiveMode,
			},
		}
	}

	config.Contexts[contextName] = &api.Context{
		Cluster:  clusterName,
		AuthInfo: userAndContext,
	}
	config.CurrentContext = contextName

	return clientcmd.ModifyConfig(pathOptions, *config, false)
}
