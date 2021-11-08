package libacherus

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	"golang.org/x/crypto/ssh/terminal"
)

func ListContainer(globalOptions *AcherusGlobalOptions) {

	containerListOptions := types.ContainerListOptions{
		All:     true,
		Filters: filters.NewArgs(filters.KeyValuePair{Key: "ancestor", Value: "zblurx/acherus"}, filters.KeyValuePair{Key: "ancestor", Value: "acherus-local"}),
	}

	containers, err := globalOptions.DockerClient.ContainerList(globalOptions.Context, containerListOptions)
	if err != nil {
		panic(err)
	}

	var data [][]string
	for _, container := range containers {

		var name string
		for i, e := range container.Names {
			if i > 1 {
				name += "\n"
			}
			name += e
		}

		data = append(data, []string{
			name,
			container.Image,
			container.ID[0:12],
			container.Status,
		})
	}
	tableOutput([]string{"Name", "Image", "ID", "Status"}, data)
}

func CreateContainer(globalOptions *AcherusGlobalOptions, commandOptions *AcherusGoOptions) (string, error) {
	environmentVariables := []string{
		"DISPLAY=" + os.Getenv("DISPLAY"),
		"QT_X11_NO_MITSHM=1",
		"_X11_NO_MITSHM=1",
		"_MITSHM=0",
	}

	fullDirPath := filepath.Join(globalOptions.AcherusDir, commandOptions.ContainerTag)

	var mountList []mount.Mount
	if commandOptions.Mount != "" {
		customMount := strings.Split(commandOptions.Mount, ":")
		if len(customMount) != 2 {
			return "", fmt.Errorf("mount option not well formated, should be like that -> source:dest")
		}
		mountList = []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: "/tmp/.X11-unix",
				Target: "/tmp/.X11-unix",
			},
			{
				Type:   mount.TypeBind,
				Source: fullDirPath,
				Target: "/data",
			},
			{
				Type:   mount.TypeBind,
				Source: customMount[0],
				Target: customMount[1],
			},
		}
	} else {
		mountList = []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: "/tmp/.X11-unix",
				Target: "/tmp/.X11-unix",
			},
			{
				Type:   mount.TypeBind,
				Source: fullDirPath,
				Target: "/data",
			},
		}
	}

	var image string
	if commandOptions.Local {
		image = "acherus-local"
	} else {
		image = "zblurx/acherus:latest"
	}

	config := &container.Config{
		Image:        image,
		Tty:          true,
		OpenStdin:    true,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		StdinOnce:    false,
		Hostname:     commandOptions.ContainerTag,
		Cmd:          commandOptions.Command,
		Env:          environmentVariables,
	}

	var networkmode container.NetworkMode = "host"
	if commandOptions.Nat {
		networkmode = "bridge"
	}

	hostconfig := &container.HostConfig{
		Mounts:      mountList,
		NetworkMode: networkmode,
		IpcMode:     "host",
		Privileged:  commandOptions.Privileged,
	}

	resp, err := globalOptions.DockerClient.ContainerCreate(globalOptions.Context, config, hostconfig, nil, nil, commandOptions.ContainerTag)
	if err != nil {
		return "", err
	}
	return resp.ID, nil
}

func AttachContainer(globalOptions *AcherusGlobalOptions, respID string) (types.HijackedResponse, error) {
	waiter, err := globalOptions.DockerClient.ContainerAttach(context.Background(), respID, types.ContainerAttachOptions{
		Stderr: true,
		Stdout: true,
		Stdin:  true,
		Stream: true,
	})
	if err != nil {
		return waiter, err
	}

	return waiter, nil
}

func BindDisplay(globalOptions *AcherusGlobalOptions, respID string) error {
	containerInfos, err := globalOptions.DockerClient.ContainerInspect(globalOptions.Context, respID)
	if err != nil {
		return err
	}
	cmd := exec.Command("xhost", "+local:"+containerInfos.Config.Hostname)
	err = cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func StartContainerAndAttach(respID string, globalOptions *AcherusGlobalOptions, commandOptions *AcherusGoOptions) error {
	waiter, err := AttachContainer(globalOptions, respID)
	if err != nil {
		return err
	}
	defer waiter.Close()

	go io.Copy(os.Stdout, waiter.Reader)

	if err = globalOptions.DockerClient.ContainerStart(globalOptions.Context, respID, types.ContainerStartOptions{}); err != nil {
		return err
	}

	oldState, fd, err := SetupTty(globalOptions, respID, waiter, false)
	if err != nil {
		return err
	}

	statusCh, errCh := globalOptions.DockerClient.ContainerWait(globalOptions.Context, respID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return err
		}
	case <-statusCh:
	}

	if terminal.IsTerminal(fd) {
		terminal.Restore(fd, oldState)
	}

	return nil
}

func SetupTty(globalOptions *AcherusGlobalOptions, respID string, waiter types.HijackedResponse, exec bool) (*terminal.State, int, error) {
	fd := int(os.Stdin.Fd())

	width, height, err := terminal.GetSize(int(os.Stdin.Fd()))
	resizeOptions := types.ResizeOptions{
		Height: uint(height),
		Width:  uint(width),
	}
	if exec {
		err = globalOptions.DockerClient.ContainerExecResize(globalOptions.Context, respID, resizeOptions)
		if err != nil {
			return nil, -1, err
		}
	} else {
		err = globalOptions.DockerClient.ContainerResize(globalOptions.Context, respID, resizeOptions)
		if err != nil {
			return nil, -1, err
		}
	}

	var oldState *terminal.State

	if terminal.IsTerminal(fd) {
		oldState, err = terminal.MakeRaw(fd)
		if err != nil {
			return nil, -1, err
		}
		go func() {
			consoleReader := bufio.NewReader(os.Stdin)
			for {
				var input byte
				if input, err = consoleReader.ReadByte(); err != nil {
					fmt.Println(err.Error())
				}
				waiter.Conn.Write([]byte{input})
				if exec {
					err = globalOptions.DockerClient.ContainerExecResize(globalOptions.Context, respID, resizeOptions)
					if err != nil {
						fmt.Println(err.Error())
					}
				} else {
					err = globalOptions.DockerClient.ContainerResize(globalOptions.Context, respID, resizeOptions)
					if err != nil {
						fmt.Println(err.Error())
					}
				}
			}
		}()
	}
	return oldState, fd, nil
}

func InitContainerDir(globalOptions *AcherusGlobalOptions, commandOptions *AcherusGoOptions) error {
	if !IsDirCreated(globalOptions.AcherusDir) {
		globalOptions.Logger.Output("Acherus directory does not exists\n", "verbose", "*", "")
		globalOptions.Logger.Output("Creating directory "+globalOptions.AcherusDir+"\n", "verbose", "*", "")
		err := CreateDir(globalOptions.AcherusDir)
		if err != nil {
			return err
		}
	} else {
		globalOptions.Logger.Output("Acherus directory exists\n", "verbose", "*", "")
	}

	fullPath := filepath.Join(globalOptions.AcherusDir, commandOptions.ContainerTag)

	if !IsDirCreated(fullPath) {
		globalOptions.Logger.Output("Container directory does not exists\n", "verbose", "*", "")
		globalOptions.Logger.Output("Creating directory "+fullPath+"\n", "verbose", "*", "")
		err := CreateDir(fullPath)
		if err != nil {
			return err
		}
	} else {
		globalOptions.Logger.Output("Container directory exists\n", "verbose", "*", "")
	}
	return nil
}

func FindContainerByName(globalOptions *AcherusGlobalOptions, containerTag string) (exists bool, container types.Container, err error) {
	containerListOptions := types.ContainerListOptions{
		All:     true,
		Filters: filters.NewArgs(filters.KeyValuePair{Key: "name", Value: containerTag}),
	}

	containerList, err := globalOptions.DockerClient.ContainerList(globalOptions.Context, containerListOptions)
	if err != nil {
		return false, types.Container{}, err
	}

	for _, e := range containerList {
		for _, f := range e.Names {
			if f == "/"+containerTag {
				return true, e, nil
			}
		}
	}

	return false, types.Container{}, nil
}

func ContainerExec(globalOptions *AcherusGlobalOptions, originalRespId string, commandOptions *AcherusGoOptions) error {

	execConfig := types.ExecConfig{
		Cmd:          commandOptions.Command,
		Tty:          true,
		AttachStdin:  true,
		AttachStderr: true,
		AttachStdout: true,
		Detach:       false,
	}
	resp, err := globalOptions.DockerClient.ContainerExecCreate(globalOptions.Context, "/"+commandOptions.ContainerTag, execConfig)
	if err != nil {
		return err
	}

	waiter, err := globalOptions.DockerClient.ContainerExecAttach(globalOptions.Context, resp.ID, types.ExecStartCheck{Tty: true, Detach: false})
	if err != nil {
		return err
	}

	defer waiter.Close()

	go io.Copy(os.Stdout, waiter.Reader)

	err = globalOptions.DockerClient.ContainerExecStart(globalOptions.Context, resp.ID, types.ExecStartCheck{Tty: true, Detach: false})
	if err != nil {
		return err
	}
	oldState, fd, err := SetupTty(globalOptions, resp.ID, waiter, true)
	if err != nil {
		return err
	}

	WaitExecContainer(globalOptions, resp.ID, commandOptions)

	if terminal.IsTerminal(fd) {
		terminal.Restore(fd, oldState)
	}
	return nil
}

func WaitExecContainer(globalOptions *AcherusGlobalOptions, execID string, commandOptions *AcherusGoOptions) error {
	for {
		execInspect, err := globalOptions.DockerClient.ContainerExecInspect(globalOptions.Context, execID)
		if err != nil {
			return err
		}

		if execInspect.Running {
			continue
		}

		if execInspect.ExitCode > 0 {
			return fmt.Errorf("Command exited with error code %v", execInspect.ExitCode)
		}
		break
	}
	return nil
}

func StopContainer(globalOptions *AcherusGlobalOptions, commandOptions *AcherusSuspendOptions) (err error) {
	exists, container, err := FindContainerByName(globalOptions, commandOptions.ContainerTag)
	if err != nil {
		return err
	}

	if !exists {
		return fmt.Errorf("Container %s does not exists", commandOptions.ContainerTag)
	}

	if container.State != "running" {
		return fmt.Errorf("This container is not running")
	}
	err = globalOptions.DockerClient.ContainerStop(context.Background(), container.ID, nil)
	if err != nil {
		return err
	}

	return nil
}

func DeleteContainer(globalOptions *AcherusGlobalOptions, commandOptions *AcherusDestroyOptions) (err error) {
	exists, container, err := FindContainerByName(globalOptions, commandOptions.ContainerTag)
	if err != nil {
		return err
	}

	if !exists {
		return fmt.Errorf("Container %s does not exists", commandOptions.ContainerTag)
	}

	if container.State == "running" && !commandOptions.Force {
		return fmt.Errorf("This container is running")
	}

	containerRemoveOptions := types.ContainerRemoveOptions{
		Force: commandOptions.Force,
	}

	err = globalOptions.DockerClient.ContainerRemove(globalOptions.Context, commandOptions.ContainerTag, containerRemoveOptions)
	if err != nil {
		return err
	}

	if commandOptions.Purge {
		question := fmt.Sprintf("Are you sure you want to delete persistant data for container %s ?", commandOptions.ContainerTag)
		checkConfirmation := AskForConfirmation(globalOptions, question)
		if checkConfirmation {
			fullPath := filepath.Join(globalOptions.AcherusDir, commandOptions.ContainerTag)

			if IsDirCreated(fullPath) {
				DeleteDir(fullPath)
			}
		}

	}
	return nil
}
