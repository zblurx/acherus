package cmd

import (
	"github.com/spf13/cobra"
	"github.com/zblurx/acherus/libacherus"
)

var cmdReset *cobra.Command

func runReset(cmd *cobra.Command, args []string) error {
	globalOptions, commandOptions, err := getResetOptions()
	if err != nil {
		globalOptions.Logger.ClassicOutput(err.Error(), "fail")
		return nil
	}

	err = libacherus.CheckDockerDeamon()
	if err != nil {
		globalOptions.Logger.ClassicOutput(err.Error(), "fail")
		return nil
	}

	err = libacherus.ResetImage(globalOptions, commandOptions)
	if err != nil {
		globalOptions.Logger.ClassicOutput(err.Error(), "fail")
		return nil
	}

	return nil
}

func getResetOptions() (*libacherus.AcherusGlobalOptions, *libacherus.AcherusResetOptions, error) {
	globalOptions, err := getGlobalOptions()
	if err != nil {
		return nil, nil, err
	}

	commandOptions := libacherus.NewResetOptions()

	return globalOptions, commandOptions, nil
}

func init() {
	cmdReset = &cobra.Command{
		Use:   "reset",
		Short: "Reset Image",
		RunE:  runReset,
	}

	rootCmd.AddCommand(cmdReset)
}
