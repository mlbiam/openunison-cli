/*
Copyright © 2025 Tremolo Security, Inc
*/
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/tremolosecurity/openunison-cli/cmd"
)

func main() {
	cmd.Execute()

	// fmt.Print("Starting idp\n")

	// idp, err := oulogintest.StartTestOIDCProvider()

	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Printf("Server URL: %s\n", idp.Server.URL)
	// fmt.Printf("Issuer URL: %s\n", idp.Issuer)

	// bufio.NewReader(os.Stdin).ReadBytes('\n')

	// pem, _, _ := getPEMFromTLSCertificate(idp.Server.TLS.Certificates[0])

	// fmt.Print(string(pem))

	// fmt.Print("Hit enter to shutdown")
	// idp.Close()
	// fmt.Print("Shutdown")

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
