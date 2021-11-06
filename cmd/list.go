package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/zblurx/acherus/libacherus"
)

var cmdList *cobra.Command

func runList(cmd *cobra.Command, args []string) error {
	globalOptions, err := getListOptions()
	if err != nil {
		globalOptions.Logger.ClassicOutput(err.Error(), "fail")
		return nil
	}

	err = libacherus.CheckDockerDeamon()
	if err != nil {
		globalOptions.Logger.ClassicOutput(err.Error(), "fail")
		return nil
	}

	globalOptions.Logger.ClassicOutput("Image List", "default")
	fmt.Println()
	libacherus.ListImage(globalOptions)
	fmt.Println()
	globalOptions.Logger.ClassicOutput("Container List", "default")
	fmt.Println()
	libacherus.ListContainer(globalOptions)
	fmt.Println()
	return nil
}

func getListOptions() (*libacherus.AcherusGlobalOptions, error) {
	globalOptions, err := getGlobalOptions()
	if err != nil {
		return nil, err
	}

	return globalOptions, nil
}

func init() {
	cmdList = &cobra.Command{
		Use:   "list",
		Short: "List available container",
		RunE:  runList,
	}
	rootCmd.AddCommand(cmdList)
}
