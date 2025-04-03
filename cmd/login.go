/*
Copyright © 2025 Tremolo Security, Inc
*/
package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"

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

		session, err := outokens.LoginToOpenUnison(host, caCertPath, context.TODO())

		if err != nil {
			fmt.Printf("Error logging in: %v\n", err)
			os.Exit(1)
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
	loginCmd.PersistentFlags().StringVar(&contextName, "context-name", "", "An alternative name for the context in the kubeconfig file instead of user@cluster host name")
}
