package cmd

import (
	"github.com/spf13/cobra"
	"github.com/zblurx/acherus/libacherus"
)

var cmdSuspend *cobra.Command

func runSuspend(cmd *cobra.Command, args []string) error {
	globalOptions, commandOptions, err := getSuspendOptions()
	if err != nil {
		globalOptions.Logger.ClassicOutput(err.Error(), "fail")
		return nil
	}

	err = libacherus.CheckDockerDeamon()
	if err != nil {
		globalOptions.Logger.ClassicOutput(err.Error(), "fail")
		return nil
	}

	err = libacherus.StopContainer(globalOptions, commandOptions)
	if err != nil {
		globalOptions.Logger.ClassicOutput(err.Error(), "fail")
		return nil
	}

	return nil
}

func getSuspendOptions() (*libacherus.AcherusGlobalOptions, *libacherus.AcherusSuspendOptions, error) {
	globalOptions, err := getGlobalOptions()
	if err != nil {
		return nil, nil, err
	}

	commandOptions := libacherus.NewSuspendOptions()

	tag, err := cmdSuspend.Flags().GetString("tag")
	if err != nil {
		return nil, nil, err
	}
	if tag != "" {
		commandOptions.ContainerTag += "-" + tag
	}

	return globalOptions, commandOptions, nil
}

func init() {
	cmdSuspend = &cobra.Command{
		Use:   "suspend",
		Short: "Suspend targeted Acherus Container",
		RunE:  runSuspend,
	}

	cmdSuspend.Flags().StringP("tag", "t", "", "Tag the specifc container (default \"acherus\")")

	rootCmd.AddCommand(cmdSuspend)
}
