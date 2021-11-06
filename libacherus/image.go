package libacherus

import (
	"bufio"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/pkg/archive"
)

func ListImage(globalOptions *AcherusGlobalOptions) {
	imageListOptions := types.ImageListOptions{
		Filters: filters.NewArgs(filters.KeyValuePair{Key: "reference", Value: "acherus*"}),
	}
	images, err := globalOptions.DockerClient.ImageList(globalOptions.Context, imageListOptions)
	if err != nil {
		panic(err)
	}

	var data [][]string
	for _, image := range images {
		var tags string
		for i, e := range image.RepoTags {
			if i > 1 {
				tags += " - "
			}
			tags += e
		}
		data = append(data, []string{
			strings.Split(image.ID, ":")[1][0:12],
			tags,
			sizeFormat(image.Size),
		})
	}
	tableOutput([]string{"ID", "Tags", "Size"}, data)
}

func PullImage(globalOptions *AcherusGlobalOptions) (err error) {

	reader, err := globalOptions.DockerClient.ImagePull(globalOptions.Context, "zblurx/acherus:latest", types.ImagePullOptions{})
	defer reader.Close()
	if err != nil {
		return err
	}

	err = globalOptions.Logger.LoadingOutput(bufio.NewScanner(reader), "Pulling Acherus. Can take some time...")
	if err != nil {
		return err
	}

	globalOptions.Logger.Output("Ready !\n", "success", "*", "\n")
	return nil
}

func BuildImage(globalOptions *AcherusGlobalOptions, commandOptions *AcherusInitOptions) (err error) {
	tar, err := archive.TarWithOptions(".", &archive.TarOptions{})
	if err != nil {
		return err
	}

	opts := types.ImageBuildOptions{
		Dockerfile: commandOptions.DockerfilePath,
		Tags:       []string{"acherus"},
		Remove:     true,
	}

	res, err := globalOptions.DockerClient.ImageBuild(globalOptions.Context, tar, opts)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	err = globalOptions.Logger.LoadingOutput(bufio.NewScanner(res.Body), "Building Acherus. Can take some time...")
	if err != nil {
		return err
	}

	globalOptions.Logger.Output("Ready !\n", "success", "*", "\n")
	return nil
}

func ResetImage(globalOptions *AcherusGlobalOptions, commandOptions *AcherusResetOptions) (err error) {

	_, err = globalOptions.DockerClient.ImageRemove(globalOptions.Context, "acherus", types.ImageRemoveOptions{})
	if err != nil {
		return err
	}

	return nil
}
