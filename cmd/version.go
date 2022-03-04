package cmd

import (
	"github.com/spf13/cobra"
)

var cmdVersion *cobra.Command

var VERSION string = "0.1.0"

func runVersion(cmd *cobra.Command, args []string) error {
	globalOptions, err := getListOptions()
	if err != nil {
		globalOptions.Logger.ClassicOutput(err.Error(), "fail")
		return nil
	}

	globalOptions.Logger.ClassicOutput(VERSION, "default")

	return nil
}

func init() {
	cmdVersion = &cobra.Command{
		Use:   "version",
		Short: "Acherus version",
		RunE:  runVersion,
	}
	rootCmd.AddCommand(cmdVersion)
}
