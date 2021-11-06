package libacherus

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

func CheckDockerDeamon() error {
	c, err := net.Dial("unix", "/var/run/docker.sock")
	if err != nil {
		if err.Error() == "dial unix /var/run/docker.sock: connect: no such file or directory" {
			return fmt.Errorf("Docker is not running or not installed")
		} else if err.Error() == "dial unix /var/run/docker.sock: connect: permission denied" {
			return fmt.Errorf("Cannot run docker: Permission Denied")
		} else {
			return fmt.Errorf("Unknown error: %v", err.Error())
		}
	}
	c.Close()
	return nil
}

func IsDirCreated(dir string) bool {
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func CreateDir(dir string) error {
	err := os.Mkdir(dir, 0775)
	if err != nil {
		return err
	}
	return nil
}

func DeleteDir(dir string) error {
	err := os.RemoveAll(dir)
	if err != nil {
		return err
	}
	return nil
}

func AskForConfirmation(globalOptions *AcherusGlobalOptions, s string) bool {
	reader := bufio.NewReader(os.Stdin)

	for {
		globalOptions.Logger.Output(s+" [y/n]: ", "default", "*", "\n")

		response, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		response = strings.ToLower(strings.TrimSpace(response))

		if response == "y" || response == "yes" {
			return true
		}
		return false
	}
	return false
}
