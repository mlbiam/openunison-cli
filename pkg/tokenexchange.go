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
		Expires string `json:"expires"`
		JWT     string `json:"jwt"`
	} `json:"token"`
}

// ExchangeToken reads a JWT from jwtPath, calls serviceURL with it as a Bearer token,
// requires HTTP 200, then writes token.jwt and expires into outDir.
// If caPEMPath is a non-empty path, it is used as an additional trust anchor for TLS.
func ExchangeToken(jwtPath, serviceURL, outDir, caPEMPath string) error {
	jwtBytes, err := os.ReadFile(jwtPath)
	if err != nil {
		return fmt.Errorf("read jwt file: %w", err)
	}
	token := strings.TrimSpace(string(jwtBytes))

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("ensure outDir: %w", err)
	}

	// HTTP client, optionally with custom RootCAs
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{},
	}
	if caPEMPath != "" {
		caPEM, err := os.ReadFile(caPEMPath)
		if err != nil {
			return fmt.Errorf("read CA PEM: %w", err)
		}
		cp, err := x509.SystemCertPool()
		if err != nil || cp == nil {
			cp = x509.NewCertPool()
		}
		if ok := cp.AppendCertsFromPEM(caPEM); !ok {
			return errors.New("failed to append CA PEM")
		}
		tr.TLSClientConfig.RootCAs = cp
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
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
	if err := os.WriteFile(filepath.Join(outDir, "token.jwt"), []byte(er.Token.JWT), 0o600); err != nil {
		return fmt.Errorf("write token.jwt: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "expires"), []byte(er.Token.Expires), 0o600); err != nil {
		return fmt.Errorf("write expires: %w", err)
	}

	return nil
}

// MaintainToken runs indefinitely until it receives SIGINT, SIGTERM, or SIGUSR1.
// Every loop it checks <outDir>/expires; if missing or expiring within rotateMinutes,
// it calls ExchangeToken. Then it sleeps sleepSeconds and repeats.
func MaintainToken(jwtPath, serviceURL, outDir, caPEMPath string, sleepSeconds int, rotateMinutes int) error {
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
					logger.Info("Not generating a new token yet")
				}
			}
		}

		if shouldExchange {
			if err := ExchangeToken(jwtPath, serviceURL, outDir, caPEMPath); err != nil {
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
