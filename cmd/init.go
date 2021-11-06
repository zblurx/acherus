package cmd

import (
	"github.com/spf13/cobra"
	"github.com/zblurx/acherus/libacherus"
)

var cmdInit *cobra.Command

func runInit(cmd *cobra.Command, args []string) error {
	globalOptions, commandOptions, err := getInitOptions()
	if err != nil {
		globalOptions.Logger.ClassicOutput(err.Error(), "fail")
		return nil
	}

	err = libacherus.CheckDockerDeamon()
	if err != nil {
		globalOptions.Logger.ClassicOutput(err.Error(), "fail")
		return nil
	}

	if commandOptions.Local {
		err = libacherus.BuildImage(globalOptions, commandOptions)
		if err != nil {
			globalOptions.Logger.ClassicOutput(err.Error(), "fail")
			return nil
		}
	} else {
		err = libacherus.PullImage(globalOptions)
		if err != nil {
			globalOptions.Logger.ClassicOutput(err.Error(), "fail")
			return nil
		}
	}

	return nil
}

func getInitOptions() (*libacherus.AcherusGlobalOptions, *libacherus.AcherusInitOptions, error) {
	globalOptions, err := getGlobalOptions()
	if err != nil {
		return nil, nil, err
	}

	commandOptions := libacherus.NewInitOptions()
	commandOptions.Local, err = cmdInit.Flags().GetBool("local")
	if err != nil {
		return nil, nil, err
	}

	commandOptions.DockerfilePath, err = cmdInit.Flags().GetString("dockerfile-path")
	if err != nil {
		return nil, nil, err
	}

	return globalOptions, commandOptions, nil
}

func init() {
	cmdInit = &cobra.Command{
		Use:   "init",
		Short: "Build image",
		RunE:  runInit,
	}
	cmdInit.Flags().BoolP("local", "l", false, "Load Acherus from a local Dockerfile")
	cmdInit.Flags().StringP("dockerfile-path", "d", "", "Dockerfile path")
	rootCmd.AddCommand(cmdInit)
}
