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

type OutputSegment struct {
	ImagePullStream                                *ImagePullStream
	Downloading, Downloaded, Extracting, Extracted bool
}

type OutputSegmentMap map[string]*OutputSegment

func newOutputSegmentMap() *OutputSegmentMap {
	return &OutputSegmentMap{}
}

func newOutputSegment() *OutputSegment {
	return &OutputSegment{
		ImagePullStream: &ImagePullStream{},
		Downloading:     false,
		Downloaded:      false,
		Extracting:      false,
		Extracted:       false,
	}
}

type LoadingBarControlContent struct {
	CurrentValue, TotalValue int64
	Data                     map[string]*ImagePullProgressDetail
	Bar                      *pb.ProgressBar
	StatusMessage            string
	Finish                   bool
}

func newLoadingBarControlContent(statusMessage string) *LoadingBarControlContent {
	tmpBar := pb.New(0)
	tmpBar.Set(pb.Bytes, true)
	tmpBar.Set(pb.SIBytesPrefix, true)
	return &LoadingBarControlContent{
		Data:          make(map[string]*ImagePullProgressDetail),
		Bar:           tmpBar,
		StatusMessage: statusMessage,
	}
}

func (bar *LoadingBarControlContent) refreshDataFromSegment(segments OutputSegmentMap, out AcherusOutput) {
	bar.TotalValue = 0
	bar.CurrentValue = 0
	status := false

	for i, e := range bar.Data {
		bar.CurrentValue += e.Current
		bar.TotalValue += e.Total
		if segments[i].ImagePullStream.Status != bar.StatusMessage {
			status = true
		}
	}

	if status {
		if bar.Bar.Total() <= bar.TotalValue {
			bar.Bar.SetTotal(bar.TotalValue)
		}
		out.Output(bar.StatusMessage+"...\n", "verbose", "*", "\n")
		if !bar.Bar.IsStarted() {

			bar.Bar.Start()
		}
		bar.Bar.SetCurrent(bar.CurrentValue)
	}
	return
}

func (bar *LoadingBarControlContent) finishBar() {
	bar.Bar.SetCurrent(bar.TotalValue)
	bar.Bar.Finish()
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

		downloadBar := newLoadingBarControlContent("Downloading")
		extractBar := newLoadingBarControlContent("Extracting")

		var segments OutputSegmentMap = make(OutputSegmentMap)
		var lastLine string

		for scanner.Scan() {
			lastLine = scanner.Text()
			streamLine := &ImagePullStream{}
			json.Unmarshal([]byte(lastLine), streamLine)
			if _, check := segments[streamLine.Id]; !check {
				segments[streamLine.Id] = newOutputSegment()
			}
			if streamLine.Status != "" && streamLine.Status != "\n" {
				segments[streamLine.Id].ImagePullStream = streamLine
				if streamLine.Status == "Downloading" {
					segments[streamLine.Id].Downloading = true
				} else if streamLine.Status == "Extracting" && segments[streamLine.Id].Downloaded {
					segments[streamLine.Id].Extracting = true
				} else if segments[streamLine.Id].Downloading && !segments[streamLine.Id].Downloaded {
					segments[streamLine.Id].Downloaded = true
				} else if segments[streamLine.Id].Extracting && !segments[streamLine.Id].Extracted {
					segments[streamLine.Id].Extracted = true
				}
			}

			downloadFinished := true
			extractFinished := true

			for _, e := range segments {
				if !e.Downloaded {
					downloadFinished = false
				}
				if !e.Extracted {
					extractFinished = false
				}
				if e.Downloading {
					downloadBar.Data[e.ImagePullStream.Id] = &e.ImagePullStream.ProgressDetail
				} else if e.Extracting {
					extractBar.Data[e.ImagePullStream.Id] = &e.ImagePullStream.ProgressDetail
				}
			}

			if downloadFinished {
				if !downloadBar.Finish {
					downloadBar.Bar.Finish()
					downloadBar.Finish = true
					fmt.Println()
				}
				if extractFinished {
					if !extractBar.Finish {
						extractBar.Bar.Finish()
						extractBar.Finish = true
						fmt.Println()
					}
				} else {
					extractBar.refreshDataFromSegment(segments, out)
				}
			} else {
				downloadBar.refreshDataFromSegment(segments, out)
			}
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
