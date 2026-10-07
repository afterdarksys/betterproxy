package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	scriptPath string
	verbose    bool
	outputJSON bool
	daemonURL  string
)

var rootCmd = &cobra.Command{
	Use:   "betterproxy",
	Short: "BetterProxy: Starlark email filtering engine",
	Long: `BetterProxy filters email with Starlark rules. It runs offline against
sample messages and mailboxes, as an SMTP proxy in front of any mail server,
or as a library.

Capabilities:
  - Starlark rules with roughly 200 mail-aware builtins
  - Header validation: RFC conformance, spoofing, and injection checks
  - Cryptographic verification of SPF, DKIM, DMARC and DANE
  - Human-versus-automated sender classification
  - TF-IDF classification with optional BERT tokenization
  - mbox and Maildir processing, JSON output for automation

Examples:
  # Test a script against a sample message
  betterproxy test --script=filter.star --subject="Buy now"

  # Inspect a real message: validation, authentication, classification
  betterproxy inspect --eml=message.eml --verify

  # Verify sender authentication only
  betterproxy verify --eml=message.eml --client-ip=192.0.2.1

  # Process a mailbox
  betterproxy process --script=filter.star --mbox=/var/mail/user

  # Train a spam classifier from labelled mailboxes
  betterproxy train --spam=spam.mbox --ham=ham.mbox --out=model.json.gz

  # Check a script for errors without running it
  betterproxy lint --script=filter.star`,
	SilenceUsage: true,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("betterproxy %s\n", Version)
		fmt.Printf("built:      %s\n", BuildTime)
		fmt.Printf("go version: %s\n", GoVersion)
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVar(&outputJSON, "json", false, "Emit results as JSON")
	rootCmd.AddCommand(versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}
