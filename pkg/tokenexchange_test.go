//go:build linux || darwin

package outokens

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func writeServerCertPEM(t *testing.T, srv *httptest.Server, path string) {
	t.Helper()
	state := srv.Client().Transport.(*http.Transport).TLSClientConfig
	if state == nil {
		// Build a TLS config that trusts the server's cert (httptest.NewTLSServer installs it in srv.Certificate())
	}
	// Extract leaf cert from server
	cert := srv.Certificate()
	if cert == nil {
		t.Fatalf("no server certificate")
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
		t.Fatalf("write pem: %v", err)
	}
}

func TestExchangeToken_Success_WithCustomCA(t *testing.T) {
	// Fake token data
	fakeJWT := "abc.def.ghi"
	exp := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339)
	respJSON := fmt.Sprintf(`{"displayName":"x","token":{"expires":"%s","jwt":"%s"}}`, exp, "SERVICE.JWT.VALUE")

	// HTTPS test server returning 200 + JSON
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+fakeJWT {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(respJSON))
	}))
	defer ts.Close()

	// Prepare CA cert file (trust the test server)
	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "server-ca.pem")
	writeServerCertPEM(t, ts, caPath)

	// Prepare JWT file and output dir
	jwtPath := filepath.Join(tmpDir, "in.jwt")
	if err := os.WriteFile(jwtPath, []byte(fakeJWT), 0o600); err != nil {
		t.Fatalf("write jwt: %v", err)
	}
	outDir := filepath.Join(tmpDir, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mk out: %v", err)
	}

	// Exchange
	if err := ExchangeToken(jwtPath, ts.URL, outDir, caPath); err != nil {
		t.Fatalf("ExchangeToken error: %v", err)
	}

	// Verify files
	gotJWT, err := os.ReadFile(filepath.Join(outDir, "token.jwt"))
	if err != nil {
		t.Fatalf("read token.jwt: %v", err)
	}
	if string(gotJWT) != "SERVICE.JWT.VALUE" {
		t.Fatalf("jwt mismatch, got %q", string(gotJWT))
	}

	gotExp, err := os.ReadFile(filepath.Join(outDir, "expires"))
	if err != nil {
		t.Fatalf("read expires: %v", err)
	}
	if string(gotExp) != exp {
		t.Fatalf("expires mismatch, got %q want %q", string(gotExp), exp)
	}
}

func TestExchangeToken_Non200(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer ts.Close()

	// Write CA bundle trusting the test server.
	// We can build a pool with the server cert and ensure client trusts it.
	cert := ts.Certificate()
	cp := x509.NewCertPool()
	cp.AddCert(cert)
	// Save the cert so ExchangeToken can load it
	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "server-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644); err != nil {
		t.Fatalf("write pem: %v", err)
	}

	jwtPath := filepath.Join(tmpDir, "in.jwt")
	if err := os.WriteFile(jwtPath, []byte("abc"), 0o600); err != nil {
		t.Fatalf("write jwt: %v", err)
	}
	outDir := filepath.Join(tmpDir, "out")
	_ = os.MkdirAll(outDir, 0o755)

	err := ExchangeToken(jwtPath, ts.URL, outDir, caPath)
	if err == nil {
		t.Fatal("expected error on non-200, got nil")
	}
}

func TestMaintainToken_Lifecycle_StopWithUSR1(t *testing.T) {
	// Build a server that always returns a short-lived token (expires soon)
	resp := func(exp time.Time) string {
		return fmt.Sprintf(`{"displayName":"x","token":{"expires":"%s","jwt":"TOK"}}`, exp.UTC().Format(time.RFC3339))
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// each call: expires 2 minutes from now
		body := resp(time.Now().UTC().Add(2 * time.Minute))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()

	// Trust server cert
	tmpDir := t.TempDir()
	cert := ts.Certificate()
	caPath := filepath.Join(tmpDir, "server-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644); err != nil {
		t.Fatalf("write pem: %v", err)
	}

	// JWT file and out dir
	jwtPath := filepath.Join(tmpDir, "in.jwt")
	if err := os.WriteFile(jwtPath, []byte("j.w.t"), 0o600); err != nil {
		t.Fatalf("write jwt: %v", err)
	}
	outDir := filepath.Join(tmpDir, "out")
	_ = os.MkdirAll(outDir, 0o755)

	// Start in background; rotate window 5 minutes so it will fetch immediately (no expires file yet).
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = MaintainToken(jwtPath, ts.URL, outDir, caPath, 1, 5)
	}()

	// Wait a bit for first fetch
	time.Sleep(500 * time.Millisecond)

	// Verify files created
	if _, err := os.Stat(filepath.Join(outDir, "token.jwt")); err != nil {
		t.Fatalf("token.jwt not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "expires")); err != nil {
		t.Fatalf("expires not created: %v", err)
	}

	// Stop loop using SIGUSR1 (captured by function only)
	proc, _ := os.FindProcess(os.Getpid())
	_ = proc.Signal(syscall.SIGUSR1)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("MaintainToken did not stop on SIGUSR1")
	}
}

// Ensure our test TLS client trusts the TLS server (sanity check for local helpers)
func init() {
	// Avoid “http: TLS handshake timeout” on older environments by ensuring a default transport with TLS11/12
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
}
