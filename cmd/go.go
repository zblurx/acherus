package cmd

import (
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/spf13/cobra"
	"github.com/zblurx/acherus/libacherus"
)

var cmdGo *cobra.Command

func runGo(cmd *cobra.Command, args []string) error {
	globalOptions, commandOptions, err := getGoOptions()
	if err != nil {
		globalOptions.Logger.ClassicOutput(err.Error(), "fail")
		return nil
	}

	err = libacherus.CheckDockerDeamon()
	if err != nil {
		globalOptions.Logger.ClassicOutput(err.Error(), "fail")
		return nil
	}

	containerExists, container, err := libacherus.FindContainerByName(globalOptions, commandOptions.ContainerTag)
	if err != nil {
		globalOptions.Logger.ClassicOutput(err.Error(), "fail")
		return nil
	}

	err = libacherus.InitContainerDir(globalOptions, commandOptions)
	if err != nil {
		globalOptions.Logger.ClassicOutput(err.Error(), "fail")
		return nil
	}

	if !containerExists {
		globalOptions.Logger.Output("Creating Acherus Container\n", "verbose", "*", "")
		container.ID, err = libacherus.CreateContainer(globalOptions, commandOptions)
		if err != nil {
			globalOptions.Logger.ClassicOutput(err.Error(), "fail")
			return nil
		}
	} else {
		globalOptions.Logger.Output("Container already exists\n", "verbose", "*", "")
		if commandOptions.Recreate {
			globalOptions.Logger.Output("Recreating Container\n", "verbose", "*", "")
			err = globalOptions.DockerClient.ContainerRemove(globalOptions.Context, commandOptions.ContainerTag, types.ContainerRemoveOptions{})
			if err != nil {
				globalOptions.Logger.ClassicOutput(err.Error(), "fail")
				return nil
			}
			container.ID, err = libacherus.CreateContainer(globalOptions, commandOptions)
			if err != nil {
				globalOptions.Logger.ClassicOutput(err.Error(), "fail")
				return nil
			}
		}
	}

	globalOptions.Logger.Output("Fitting TTY\n", "verbose", "*", "")
	err = libacherus.BindDisplay(globalOptions, container.ID)
	if err != nil {
		globalOptions.Logger.ClassicOutput(err.Error(), "fail")
		return nil
	}
	if container.State == "running" {
		globalOptions.Logger.Output("Container already running\n", "verbose", "*", "")
		globalOptions.Logger.Output("Jumping in\n", "verbose", "*", "")
		if err = libacherus.ContainerExec(globalOptions, container.ID, commandOptions); err != nil {
			globalOptions.Logger.ClassicOutput(err.Error(), "fail")
			return nil
		}
	} else {
		globalOptions.Logger.Output("Jumping in\n", "verbose", "*", "")
		if !commandOptions.Detach {
			if err = libacherus.StartContainerAndAttach(container.ID, globalOptions, commandOptions); err != nil {
				globalOptions.Logger.ClassicOutput(err.Error(), "fail")
				return nil
			}
		} else {
			globalOptions.Logger.Output("Starting container in detached mode\n", "verbose", "*", "")
			if err = globalOptions.DockerClient.ContainerStart(globalOptions.Context, container.ID, types.ContainerStartOptions{}); err != nil {
				globalOptions.Logger.ClassicOutput(err.Error(), "fail")
				return nil
			}
		}
	}

	return nil
}

func getGoOptions() (*libacherus.AcherusGlobalOptions, *libacherus.AcherusGoOptions, error) {
	globalOptions, err := getGlobalOptions()
	if err != nil {
		return nil, nil, err
	}

	commandOptions := libacherus.NewGoOptions()

	commandOptions.Detach, err = cmdGo.Flags().GetBool("detach")
	if err != nil {
		return nil, nil, err
	}

	commandOptions.Nat, err = cmdGo.Flags().GetBool("nat")
	if err != nil {
		return nil, nil, err
	}

	commandOptions.Privileged, err = cmdGo.Flags().GetBool("privileged")
	if err != nil {
		return nil, nil, err
	}

	commandOptions.NetworkAdmin, err = cmdGo.Flags().GetBool("netadmin")
	if err != nil {
		return nil, nil, err
	}

	commandOptions.Mount, err = cmdGo.Flags().GetString("mount")
	if err != nil {
		return nil, nil, err
	}

	tag, err := cmdGo.Flags().GetString("tag")
	if err != nil {
		return nil, nil, err
	}
	if tag != "" {
		commandOptions.ContainerTag += "-" + tag
	}

	command, err := cmdGo.Flags().GetString("execute")
	if err != nil {
		return nil, nil, err
	}

	if command != "" {
		commandOptions.Command = strings.Split(command, " ")
	}

	commandOptions.Local, err = cmdGo.Flags().GetBool("local")
	if err != nil {
		return nil, nil, err
	}

	commandOptions.Recreate, err = cmdGo.Flags().GetBool("recreate")
	if err != nil {
		return nil, nil, err
	}

	return globalOptions, commandOptions, nil
}

func init() {
	cmdGo = &cobra.Command{
		Use:   "go",
		Short: "Execute and attach to container",
		RunE:  runGo,
	}
	cmdGo.Flags().BoolP("detach", "d", false, "Don't attach to the container")
	cmdGo.Flags().BoolP("nat", "n", false, "Nat the container (default is binded to host)")
	cmdGo.Flags().StringP("mount", "m", "", "Mount directory into acherus container (-m \"source:dest\")")
	cmdGo.Flags().StringP("tag", "t", "", "Tag the specifc container (default \"acherus\")")
	cmdGo.Flags().StringP("execute", "e", "", "Execute specific command (default is /bin/bash)")
	cmdGo.Flags().Bool("privileged", false, "Create a container in privileged mode")
	cmdGo.Flags().BoolP("local", "l", false, "Create container based on local image")
	cmdGo.Flags().Bool("recreate", false, "Force creation of the container (if the container already exists, will delete it)")
	cmdGo.Flags().Bool("netadmin", false, "Create a container that can interact with network interfaces")
	rootCmd.AddCommand(cmdGo)
}
