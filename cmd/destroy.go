package cmd

import (
	"github.com/spf13/cobra"
	"github.com/zblurx/acherus/libacherus"
)

var cmdDestroy *cobra.Command

func runDestroy(cmd *cobra.Command, args []string) error {
	globalOptions, commandOptions, err := getDestroyOptions()
	if err != nil {
		globalOptions.Logger.ClassicOutput(err.Error(), "fail")
		return nil
	}

	err = libacherus.CheckDockerDeamon()
	if err != nil {
		globalOptions.Logger.ClassicOutput(err.Error(), "fail")
		return nil
	}

	err = libacherus.DeleteContainer(globalOptions, commandOptions)
	if err != nil {
		globalOptions.Logger.ClassicOutput(err.Error(), "fail")
		return nil
	}

	return nil
}

func getDestroyOptions() (*libacherus.AcherusGlobalOptions, *libacherus.AcherusDestroyOptions, error) {
	globalOptions, err := getGlobalOptions()
	if err != nil {
		return nil, nil, err
	}

	commandOptions := libacherus.NewDestroyOptions()

	tag, err := cmdDestroy.Flags().GetString("tag")
	if err != nil {
		return nil, nil, err
	}
	if tag != "" {
		commandOptions.ContainerTag += "-" + tag
	}

	commandOptions.Force, err = cmdDestroy.Flags().GetBool("force")
	if err != nil {
		return nil, nil, err
	}

	commandOptions.Purge, err = cmdDestroy.Flags().GetBool("purge")
	if err != nil {
		return nil, nil, err
	}

	return globalOptions, commandOptions, nil
}

func init() {
	cmdDestroy = &cobra.Command{
		Use:   "destroy",
		Short: "Delete targeted container",
		RunE:  runDestroy,
	}

	cmdDestroy.Flags().StringP("tag", "t", "", "Tag the specifc container (default \"acherus\")")
	cmdDestroy.Flags().BoolP("force", "f", false, "Force deletion of the container")
	cmdDestroy.Flags().BoolP("purge", "p", false, "Delete also persistant data")

	rootCmd.AddCommand(cmdDestroy)
}
