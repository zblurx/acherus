package libacherus

import (
	"context"
	"os"
	"path/filepath"

	"github.com/docker/docker/client"
)

type AcherusGlobalOptions struct {
	Context      context.Context
	DockerClient *client.Client
	Logger       *AcherusOutput
	AcherusDir   string
	ContainerTag string
}

func NewGlobalOptions() (*AcherusGlobalOptions, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	acherusDirPath := filepath.Join(homeDir, ".acherus")

	return &AcherusGlobalOptions{
		Context:      context.Background(),
		DockerClient: cli,
		Logger:       NewAcherusOutput(),
		AcherusDir:   acherusDirPath,
	}, nil
}

type AcherusInitOptions struct {
	Local          bool
	DockerfilePath string
}

func NewInitOptions() *AcherusInitOptions {
	return &AcherusInitOptions{}
}

type AcherusListOptions struct {
}

func NewListOptions() *AcherusListOptions {
	return &AcherusListOptions{}
}

type AcherusGoOptions struct {
	Detach                   bool
	Nat                      bool
	Mount                    string
	ContainerTag             string
	Command                  []string
	Privileged               bool
	Local                    bool
	Recreate                 bool
	Clear                    bool
	ClearWithoutConfirmation bool
	NetworkAdmin             bool
}

func NewGoOptions() *AcherusGoOptions {
	return &AcherusGoOptions{
		ContainerTag: "acherus",
		Command:      []string{"/bin/bash"},
	}
}

type AcherusSuspendOptions struct {
	ContainerTag string
}

func NewSuspendOptions() *AcherusSuspendOptions {
	return &AcherusSuspendOptions{
		ContainerTag: "acherus",
	}
}

type AcherusDestroyOptions struct {
	ContainerTag string
	Force        bool
	Purge        bool
}

func NewDestroyOptions() *AcherusDestroyOptions {
	return &AcherusDestroyOptions{
		ContainerTag: "acherus",
	}
}

type AcherusResetOptions struct {
}

func NewResetOptions() *AcherusResetOptions {
	return &AcherusResetOptions{}
}
