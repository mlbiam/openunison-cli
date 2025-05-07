/*
Copyright © 2025 Tremolo Security, Inc
*/
package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	outokens "github.com/tremolosecurity/openunison-cli/pkg"
	"go.uber.org/zap"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			fmt.Println("Usage: login <hostname>")
			os.Exit(1)
		}

		host := args[0]
		if net.ParseIP(host) == nil {
			if !regexp.MustCompile(`^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+$`).MatchString(host) {
				fmt.Printf("Invalid host: %s\n", host)
				os.Exit(1)
			}
		}

		if debug {
			logger = zap.Must(zap.NewDevelopment())
			outokens.SetLogger(true)
		} else {
			logger = zap.Must(zap.NewProduction())
			outokens.SetLogger(false)
		}
		outokens.ShowLogs = true
		fmt.Printf("Logging into OpenUnison at host: %s\n", host)

		caCert := ""

		if caCertBase64 != "" {
			certBytes, err := base64.StdEncoding.DecodeString(caCertBase64)
			if err != nil {
				fmt.Printf("Error decoding base64 CA certificate: %v\n", err)
				os.Exit(1)
			} else {
				caCert = string(certBytes)
			}
		} else if caCertPath != "" {
			caCertFile, err := os.ReadFile(caCertPath)
			if err != nil {
				fmt.Printf("Error reading CA certificate file: %v\n", err)
				os.Exit(1)
			}
			caCert = string(caCertFile)
		}

		var session *outokens.OpenUnisonSession
		var err error

		if credsBase64 != "" {
			credsBytes, err := base64.StdEncoding.DecodeString(credsBase64)
			if err != nil {
				fmt.Printf("Error decoding base64 credentials: %v\n", err)
				os.Exit(1)
			}
			credsJson := string(credsBytes)

			var ouToken outokens.OpenUnisonToken
			if err := json.NewDecoder(strings.NewReader(credsJson)).Decode(&ouToken); err != nil {
				fmt.Printf("failed to load the authenticated session: %w", err)
				os.Exit(1)
			}

			session = &ouToken.Token
			session.UserName = ouToken.UserName
			session.OidcSession, err = outokens.NewOidcSession("https://"+host+"/auth/idp/k8sIdp", "kubernetes", caCert, session.IdToken, session.RefreshToken)
			if err != nil {
				fmt.Printf("failed to create OIDC session: %w", err)
				os.Exit(1)
			}

		} else {
			session, err = outokens.LoginToOpenUnison(host, caCert, context.TODO())

			if err != nil {
				fmt.Printf("Error logging in: %v\n", err)
				os.Exit(1)
			}
		}

		pathToTempFile, err := outokens.SaveSessionToTempFile(session.OidcSession, "")
		if err != nil {
			fmt.Printf("Error saving session: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Session saved to: %s\n", pathToTempFile)

		pathToOuCli, err := getExecutablePath()
		if err != nil {
			fmt.Printf("Error getting executable path: %v\n", err)
			os.Exit(1)
		}

		err = session.SaveKubectlConfigFromSession(pathToOuCli, pathToTempFile, false, contextName, forceBeta)
		if err != nil {
			fmt.Printf("Error saving kubectl config: %v\n", err)
			os.Exit(1)
		}

	},
}

func getExecutablePath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exePath)
}

func init() {
	rootCmd.AddCommand(loginCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// loginCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// loginCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	loginCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug logging")
	loginCmd.PersistentFlags().BoolVar(&forceBeta, "auth-beta", false, "Force the kubectl configuration to use client.authentication.k8s.io/v1beta1 instead of client.authentication.k8s.io/v1")
	loginCmd.PersistentFlags().StringVar(&caCertPath, "cacert-path", "", "Full path to the CA certificate in PEM format")

	loginCmd.PersistentFlags().StringVar(&caCertBase64, "cacert-base64", "", "Base64 encoded CA certificate in PEM format")
	loginCmd.PersistentFlags().StringVar(&contextName, "context-name", "", "An alternative name for the context in the kubeconfig file instead of user@cluster host name")
	loginCmd.PersistentFlags().StringVar(&credsBase64, "creds-base64", "", "Base64 encoded JSON credentials file")
}
