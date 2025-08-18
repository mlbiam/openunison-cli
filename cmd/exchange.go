/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	outokens "github.com/tremolosecurity/openunison-cli/pkg"
)

// exchangeCmd represents the exchange command
var exchangeCmd = &cobra.Command{
	Use:   "exchange",
	Short: "Used to exchange a local token for a remote token via OpenUnison",
	Long: `This command runs a loop that will exchange a local token for a remote token via OpenUnison's token service.  it accepts:
	1. The path to the local token
	2. The URL for OpenUnison to perform the token exchange
	3. The path where to save the exchanged token to
	
	you can either set flags for how long to run for or run only once`,
	Run: func(cmd *cobra.Command, args []string) {
		pathToToken := args[0]
		tokenExchangeUrl := args[1]
		pathToSaveTo := args[2]

		fmt.Printf("PathToToken : %s\n", pathToToken)
		fmt.Printf("exchange urL : %s\n", tokenExchangeUrl)
		fmt.Printf("path to save to : %s\n", pathToSaveTo)

		if singleRun {
			err := outokens.ExchangeToken(pathToToken, tokenExchangeUrl, pathToSaveTo, caCertPath)
			if err != nil {
				panic(err)
			}
		} else {
			err := outokens.MaintainToken(pathToToken, tokenExchangeUrl, pathToSaveTo, caCertPath, secondsBetweenRuns, minutesBeforeRefresh)
			if err != nil {
				panic(err)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(exchangeCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// exchangeCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// exchangeCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	exchangeCmd.Flags().BoolVar(&singleRun, "single-run", false, "If set, only runs once.")
	exchangeCmd.Flags().StringVar(&caCertPath, "cacert-path", "", "Optional path to the PEM encoded CA cert for the OpenUnison service")
	exchangeCmd.Flags().IntVar(&secondsBetweenRuns, "seconds-between-runs", 30, "The number of seconds before checking if a token should be refreshed")
	exchangeCmd.Flags().IntVar(&minutesBeforeRefresh, "minutes-before-refresh", 5, "The number of minutes before expiring that a token should be refreshed")

}
