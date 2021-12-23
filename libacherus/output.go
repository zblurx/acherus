package libacherus

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

type ImageBuildErrorLine struct {
	Error       string                `json:"error"`
	ErrorDetail ImageBuildErrorDetail `json:"errorDetail"`
}

type ImageBuildErrorDetail struct {
	Message string `json:"message"`
}

type ImageBuildStream struct {
	Stream string `json:"stream"`
}

type ImagePullProgressDetail struct {
	Current int64 `json:"current,omitempty"`
	Total   int64 `json:"total,omitempty"`
}

type ImagePullStream struct {
	Status         string                  `json:"status"`
	Id             string                  `json:"id"`
	ProgressDetail ImagePullProgressDetail `json:"progressDetail,omitempty"`
	Progress       string                  `json:"progress,omitempty"`
}

type AcherusOutput struct {
	Verbose bool
}

func NewAcherusOutput() *AcherusOutput {
	return &AcherusOutput{}
}

func tableOutput(headers []string, data [][]string) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(headers)
	table.SetBorders(tablewriter.Border{Left: true, Top: true, Right: true, Bottom: true})
	table.SetCenterSeparator("|")
	table.AppendBulk(data)
	table.Render()
}

func sizeFormat(size int64) string {
	formatList := []string{"bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"}
	sizeFloat := float64(size)
	for _, e := range formatList {
		if sizeFloat < 1024 {

			return fmt.Sprintf("%.2f %s", sizeFloat, e)
		}
		sizeFloat = sizeFloat / 1024
	}
	return ""
}

func (out AcherusOutput) SimpleLoadingOutput(scanner *bufio.Scanner, message string) {
	for scanner.Scan() {
		modulo := time.Now().Second() % 4
		var icon string
		switch modulo {
		case 1:
			icon = "/"
		case 2:
			icon = "—"
		case 3:
			icon = "\\"
		case 0:
			icon = "|"
		}
		out.Output(message+"\r", "default", icon, "\r")
	}
}

func (out AcherusOutput) LoadingPullOutput(scanner *bufio.Scanner, message string) error {
	if out.Verbose {
		out.Output(message+"\n", "default", "*", "\r")
		var segments map[string]*ImagePullStream = make(map[string]*ImagePullStream)
		var downloadData map[string]*ImagePullProgressDetail = make(map[string]*ImagePullProgressDetail)
		var general_total, general_current int64
		var lastLine string
		var bar *pb.ProgressBar = pb.New(0)
		bar.Set(pb.Bytes, true)
		bar.Set(pb.SIBytesPrefix, true)

		for scanner.Scan() {
			lastLine = scanner.Text()
			streamLine := &ImagePullStream{}
			json.Unmarshal([]byte(lastLine), streamLine)
			if streamLine.Status != "" && streamLine.Status != "\n" {
				segments[streamLine.Id] = streamLine
			}

			for _, e := range segments {
				if e.Status == "Downloading" {
					downloadData[e.Id] = &e.ProgressDetail
				}
			}

			general_total = 0
			general_current = 0
			downloading := false
			for i, e := range downloadData {
				general_current += e.Current
				general_total += e.Total
				if segments[i].Status != "Downloading" {
					downloading = true
				}
			}

			if downloading {
				if bar.Total() <= general_total {
					bar.SetTotal(general_total)
					bar.Start()
				}
				bar.SetCurrent(general_current)
			}
		}
		errLine := &ImageBuildErrorLine{}
		json.Unmarshal([]byte(lastLine), errLine)
		if errLine.Error != "" {
			return errors.New(errLine.Error)
		}

	} else {
		out.SimpleLoadingOutput(scanner, message)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func (out AcherusOutput) LoadingBuildOutput(scanner *bufio.Scanner, message string) error {

	if out.Verbose {
		out.Output(message+"\n", "default", "*", "\r")

		var lastLine string
		for scanner.Scan() {
			lastLine = scanner.Text()
			streamLine := &ImageBuildStream{}
			json.Unmarshal([]byte(lastLine), streamLine)
			if streamLine.Stream != "" && streamLine.Stream != "\n" {
				for _, e := range strings.Split(strings.TrimSuffix(streamLine.Stream, "\n"), "'\n") {
					out.Output(e+"\n", "verbose", "*", "")
				}
			}
		}
		errLine := &ImageBuildErrorLine{}
		json.Unmarshal([]byte(lastLine), errLine)
		if errLine.Error != "" {
			return errors.New(errLine.Error)
		}
	} else {
		out.SimpleLoadingOutput(scanner, message)
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func (out AcherusOutput) ClassicOutput(message string, level string) {
	out.Output(message+"\n", level, "*", "")
}

func (out AcherusOutput) Output(message string, level string, icon string, prefix string) {
	if level == "" {
		level = "default"
	}
	switch level {
	case "default":
		fmt.Printf(prefix+"%v %v", color.HiCyanString("["+icon+"]"), color.HiWhiteString(message))
	case "success":
		fmt.Printf(prefix+"%v %v", color.HiGreenString("["+icon+"]"), color.HiGreenString(message))
	case "verbose":
		if out.Verbose {
			fmt.Printf(prefix+"%v %v", color.HiYellowString("["+icon+"]"), color.HiWhiteString(message))
		}
	case "fail":
		fmt.Printf(prefix+"%v %v", color.HiRedString("["+icon+"]"), color.HiRedString(message))
	}
}
