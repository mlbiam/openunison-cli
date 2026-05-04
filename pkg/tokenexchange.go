package outokens

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

// ExchangeResponse models the minimal JSON shape we care about.
type ExchangeResponse struct {
	DisplayName string `json:"displayName"`
	Token       struct {
		Expires    string `json:"expires"`
		JWT        string `json:"jwt"`
		Thumbprint string `json:"thumbprint"`
	} `json:"token"`
}

// ThumbprintResponse models the JSON returned from a thumbprint check
type ThumbprintResponse struct {
	Thumbprint string `json:"thumbprint"`
}

// ExchangeToken reads a JWT from jwtPath, calls serviceURL with it as a Bearer token,
// requires HTTP 200, then writes token.jwt and expires into outDir.
// If caPEMPath is a non-empty path, it is used as an additional trust anchor for TLS.
func ExchangeToken(jwtPath, serviceURL, outDir, caPEMPath string, tokenGlobalRead bool) error {
	token, client, err, shouldReturn := createHttpClient(jwtPath, outDir, caPEMPath)
	if shouldReturn {
		return err
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, serviceURL, nil)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var er ExchangeResponse
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&er); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if er.Token.JWT == "" || er.Token.Expires == "" {
		return errors.New("response missing token.jwt or token.expires")
	}

	// Write files
	var fileMode os.FileMode

	if tokenGlobalRead {
		fileMode = 0o644
	} else {
		fileMode = 0o600
	}

	if err := os.WriteFile(filepath.Join(outDir, "token.jwt"), []byte(er.Token.JWT), fileMode); err != nil {
		return fmt.Errorf("write token.jwt: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "expires"), []byte(er.Token.Expires), fileMode); err != nil {
		return fmt.Errorf("write expires: %w", err)
	}

	if er.Token.Thumbprint != "" {
		if err := os.WriteFile(filepath.Join(outDir, "thumbprint"), []byte(er.Token.Thumbprint), fileMode); err != nil {
			return fmt.Errorf("write thumbprint: %w", err)
		}
	}

	return nil
}

func createHttpClient(jwtPath string, outDir string, caPEMPath string) (string, *http.Client, error, bool) {
	jwtBytes, err := os.ReadFile(jwtPath)
	if err != nil {
		return "", nil, fmt.Errorf("read jwt file: %w", err), true
	}
	token := strings.TrimSpace(string(jwtBytes))

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", nil, fmt.Errorf("ensure outDir: %w", err), true
	}

	// HTTP client, optionally with custom RootCAs
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{},
	}
	if caPEMPath != "" {
		caPEM, err := os.ReadFile(caPEMPath)
		if err != nil {
			return "", nil, fmt.Errorf("read CA PEM: %w", err), true
		}
		cp, err := x509.SystemCertPool()
		if err != nil || cp == nil {
			cp = x509.NewCertPool()
		}
		if ok := cp.AppendCertsFromPEM(caPEM); !ok {
			return "", nil, errors.New("failed to append CA PEM"), true
		}
		tr.TLSClientConfig.RootCAs = cp
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}
	return token, client, nil, false
}

// checkThumbprint looks to see if a thumbprint is available, and if so compares the existing thumbprint to the current
// thumbprint.  Returns true if the token should be rotated.
func checkThumbprint(jwtPath, serviceURL, outDir, caPEMPath string) (bool, error) {
	// load the thumbprint from disk
	thumbprintPath := filepath.Join(outDir, "thumbprint")
	thumbprintBytes, err := os.ReadFile(thumbprintPath)
	if err != nil {
		logger.Warn("No thumbprint, assuming not supported")
		return false, nil
	}
	currentThumbprint := string(thumbprintBytes)

	// load the current thumbprint
	token, client, err, shouldReturn := createHttpClient(jwtPath, outDir, caPEMPath)
	if shouldReturn {
		return false, err
	}

	thumbprintURL := strings.TrimSuffix(serviceURL, "/token/user") + "/sig-cert"

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, thumbprintURL, nil)
	if err != nil {
		return false, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK || resp.StatusCode == http.StatusNotFound {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return false, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var thumbprintResponse ThumbprintResponse
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&thumbprintResponse); err != nil {
		return false, fmt.Errorf("decode response: %w", err)
	}

	return thumbprintResponse.Thumbprint != currentThumbprint, nil

}

// MaintainToken runs indefinitely until it receives SIGINT, SIGTERM, or SIGUSR1.
// Every loop it checks <outDir>/expires; if missing or expiring within rotateMinutes,
// it calls ExchangeToken. Then it sleeps sleepSeconds and repeats.
func MaintainToken(jwtPath, serviceURL, outDir, caPEMPath string, sleepSeconds int, rotateMinutes int, tokenGlobalRead bool) error {
	if sleepSeconds <= 0 {
		sleepSeconds = 10
	}
	if rotateMinutes < 0 {
		rotateMinutes = 0
	}

	// Signal handling (SIGUSR1 is included so tests can stop without killing the test process)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, platformSignals()...)
	defer signal.Stop(sigCh)

	sleepDur := time.Duration(sleepSeconds) * time.Second
	rotateDur := time.Duration(rotateMinutes) * time.Minute

	for {
		select {
		case <-sigCh:
			// graceful exit
			return nil
		default:
		}

		logger.Info("Checking if expired")
		shouldExchange := false
		expPath := filepath.Join(outDir, "expires")
		expBytes, err := os.ReadFile(expPath)
		if err != nil {
			// No expires file yet → need a token
			logger.Info("No expiration file, generating a new token")
			shouldExchange = true
		} else {
			// Parse RFC3339 timestamp and check remaining time
			expStr := string(expBytes)
			expAt, err := time.Parse(time.RFC3339, expStr)
			if err != nil {
				// Bad timestamp → rotate
				logger.Info("Not a valid timestamp format, generating a new token")
				shouldExchange = true
			} else {
				until := time.Until(expAt.UTC())
				logger.Info(fmt.Sprintf("Minutes until expiration: %g", until.Minutes()))
				if until <= rotateDur {
					logger.Info("Generating a new token")
					shouldExchange = true
				} else {
					thumbprintChanged, err := checkThumbprint(jwtPath, serviceURL, outDir, caPEMPath)
					if err != nil {
						logger.Error(fmt.Sprintf("Could not check thumbprint: %v\n", err))
						shouldExchange = false
					}

					if thumbprintChanged {
						logger.Info("Thumbprint changed, generating a new token")
						shouldExchange = true
					} else {
						logger.Info("Not generating a new token yet")
					}

				}
			}
		}

		if shouldExchange {
			if err := ExchangeToken(jwtPath, serviceURL, outDir, caPEMPath, tokenGlobalRead); err != nil {
				// Don’t exit; log to stderr and try again next loop
				logger.Error(fmt.Sprintf("ExchangeToken error: %v\n", err))
			}
		}

		logger.Info(fmt.Sprintf("Sleeping for %d seconds", sleepSeconds))
		// Sleep or exit on signal
		select {
		case <-sigCh:
			return nil
		case <-time.After(sleepDur):
		}
	}
}
