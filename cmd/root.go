package cmd

import (
	"github.com/spf13/cobra"
	"github.com/zblurx/acherus/libacherus"
)

var rootCmd = &cobra.Command{
	Use:          "acherus",
	SilenceUsage: true,
}

func Execute() error {
	return rootCmd.Execute()
}

func getGlobalOptions() (*libacherus.AcherusGlobalOptions, error) {
	options, err := libacherus.NewGlobalOptions()
	if err != nil {
		return nil, err
	}

	options.Logger.Verbose, err = rootCmd.Flags().GetBool("verbose")
	if err != nil {
		return nil, err
	}
	return options, nil
}

func init() {
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose mode (usefull for debugging)")
}
