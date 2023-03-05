package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {

	var (
		kubeConfig string
		namespace  string
		verbose    bool
		scoutArgs  []string
	)

	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "--kubeconfig" {
			kubeConfig = os.Args[i+1]
			i = i + 1
		} else if os.Args[i] == "--namespace" {
			namespace = os.Args[i+1]
			i = i + 1
		} else if os.Args[i] == "-v" {
			verbose = true
		} else if os.Args[i] == "--format" || os.Args[i] == "--o" || os.Args[i] == "--output" {
			log.Printf("Ignoring flag %q as it is used internally to generate the output.", os.Args[i])
			i = i + 1
		} else {
			scoutArgs = append(scoutArgs, os.Args[i])
		}
	}

	if _, err := os.Stat("results"); !errors.Is(err, os.ErrNotExist) {
		_ = os.RemoveAll("results")
	}

	if kubeConfig == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatal(err)
		}
		kubeConfig = filepath.Join(homeDir, ".kube", "config")
	}

	if verbose {
		log.Printf("kubeconfig file path: %s", kubeConfig)
		log.Printf("namespace: %s", namespace)
	}

	if _, err := os.Stat(kubeConfig); errors.Is(err, os.ErrNotExist) {
		log.Fatalf("loading kubeconfig file: %s", err)
	}

	// uses the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
	if err != nil {
		log.Fatal(err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	pods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), v1.ListOptions{})
	if err != nil {
		log.Fatal(err)
	}

	var images = make(map[string]string)
	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			if _, ok := images[container.Image]; !ok {
				images[container.Image] = container.Image
				if verbose {
					log.Println(container.Image)
				}
			}
		}
	}

	log.Printf("Analyzing a total of %d images, this may take a few seconds...", len(images))

	if err := os.MkdirAll("results", os.ModePerm); err != nil {
		log.Fatal(err)
	}

	criticalVuln := 0
	highVuln := 0
	mediumVuln := 0
	lowVuln := 0

	var wg sync.WaitGroup

	var items []Item

	for _, pod := range pods.Items {
		item := Item{
			Namespace: pod.Namespace,
			Pod: Pod{
				Name: pod.Name,
			},
		}

		for _, c := range pod.Spec.Containers {
			wg.Add(1)

			c := c

			item.Pod.Containers = append(item.Pod.Containers, Container{
				Name:  c.Name,
				Image: c.Image,
			})

			go func() {
				defer wg.Done()

				// replace the matched non-alphanumeric characters with the underscore character
				outputFile := filepath.Join("results", regexp.MustCompile(`[^a-zA-Z-0-9]+`).ReplaceAllString(c.Image, "_")+".sarif.json")

				args := []string{"scout", "cves"}
				args = append(args, scoutArgs...)
				args = append(args, "--format", "sarif", "--output", outputFile, c.Image)

				cmd := exec.Command("docker", args...)
				if err := cmd.Run(); err != nil {
					log.Fatal(err)
				}

				b, err := os.ReadFile(outputFile)
				if err != nil {
					log.Fatal(err)
				}
				var report SarifReport

				if err := json.Unmarshal(b, &report); err != nil {
					log.Fatal(err)
				}

				for _, result := range report.Runs[0].Results {
					for _, rule := range report.Runs[0].Tool.Driver.Rules {
						if rule.ID == result.RuleID {
							switch rule.Properties.CvssV3Severity {
							case "LOW":
								item.Pod.Containers[0].Vulnerabilities.Low += 1
								lowVuln += 1
							case "MEDIUM":
								item.Pod.Containers[0].Vulnerabilities.Medium += 1
								mediumVuln += 1
							case "HIGH":
								item.Pod.Containers[0].Vulnerabilities.High += 1
								highVuln += 1
							case "CRITICAL":
								item.Pod.Containers[0].Vulnerabilities.Critical += 1
								criticalVuln += 1
							}
							break
						}
					}
				}

				items = append(items, item)
			}()
		}
	}

	if verbose {
		log.Println("Waiting for all goroutines to complete")
	}

	wg.Wait()

	rowConfigAutoMerge := table.RowConfig{AutoMerge: true}
	t := table.NewWriter()
	t.AppendHeader(table.Row{"Namespace", "Pod", "Container (image)", "Vulnerabilities"}, rowConfigAutoMerge)

	for _, item := range items {
		for _, container := range item.Pod.Containers {

			criticalVulns := fmtVuln("C", container.Vulnerabilities.Critical)
			highVulns := fmtVuln("H", container.Vulnerabilities.High)
			mediumVulns := fmtVuln("M", container.Vulnerabilities.Medium)
			lowVulns := fmtVuln("L", container.Vulnerabilities.Low)
			totalVulns := container.Vulnerabilities.Critical + container.Vulnerabilities.High + container.Vulnerabilities.Medium + container.Vulnerabilities.Low
			vulns := fmt.Sprintf("%s %s %s %s (%d)", criticalVulns, highVulns, mediumVulns, lowVulns, totalVulns)

			t.AppendRow(table.Row{item.Namespace, item.Pod.Name, fmt.Sprintf("%s (%s)", container.Name, container.Image), vulns}, rowConfigAutoMerge)
		}

	}

	totalCriticalVulns := fmtVuln("C", criticalVuln)
	totalHighVulns := fmtVuln("H", highVuln)
	totalMediumVulns := fmtVuln("M", mediumVuln)
	totalLowVulns := fmtVuln("L", lowVuln)
	totalTotalVulns := criticalVuln + highVuln + mediumVuln + lowVuln
	totalVulnsFmt := fmt.Sprintf("%s %s %s %s (%d)", totalCriticalVulns, totalHighVulns, totalMediumVulns, totalLowVulns, totalTotalVulns)

	t.AppendFooter(table.Row{"", "", "Total", totalVulnsFmt})
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
	})
	t.SetStyle(table.StyleLight)
	t.Style().Options.SeparateRows = true
	t.SortBy([]table.SortBy{
		{Name: "Namespace", Mode: table.Asc},
		{Name: "Pod", Mode: table.Asc},
		{Name: "Container (image)", Mode: table.Asc},
		{Name: "Vulnerabilities", Mode: table.Asc},
	})
	fmt.Println(t.Render())
}

func fmtVuln(severitySuffix string, count int) string {
	var f func(format string, a ...interface{}) string

	switch severitySuffix {
	case "C":
		f = color.New(color.FgBlack, color.BgHiRed).SprintfFunc()
	case "H":
		f = color.New(color.FgBlack, color.BgHiMagenta).SprintfFunc()
	case "M":
		f = color.New(color.FgBlack, color.BgHiYellow).SprintfFunc()
	case "L":
		f = color.New(color.FgBlack, color.BgHiCyan).SprintfFunc()
	}

	vulnText := fmt.Sprintf("  %d%s  ", count, severitySuffix)

	if count == 0 {
		return color.New(color.FgBlack).SprintfFunc()(vulnText)
	}

	return f(vulnText)
}

type SarifReport struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				FullName       string `json:"fullName"`
				InformationURI string `json:"informationUri"`
				Name           string `json:"name"`
				Rules          []struct {
					ID               string `json:"id"`
					Name             string `json:"name"`
					ShortDescription struct {
						Text string `json:"text"`
					} `json:"shortDescription"`
					HelpURI string `json:"helpUri"`
					Help    struct {
						Text     string `json:"text"`
						Markdown string `json:"markdown"`
					} `json:"help"`
					Properties struct {
						AffectedVersion string   `json:"affected_version"`
						CvssV3Severity  string   `json:"cvssV3_severity"`
						FixedVersion    string   `json:"fixed_version"`
						Tags            []string `json:"tags"`
					} `json:"properties,omitempty"`
				} `json:"rules"`
				Version string `json:"version"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID    string `json:"ruleId"`
			RuleIndex int    `json:"ruleIndex"`
			Kind      string `json:"kind"`
			Level     string `json:"level"`
			Message   struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				LogicalLocations []struct {
					Name               string `json:"name,omitempty"`
					FullyQualifiedName string `json:"fullyQualifiedName"`
					Kind               string `json:"kind,omitempty"`
				} `json:"logicalLocations"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

type Item struct {
	Namespace string
	Pod       Pod
}

type Pod struct {
	Name       string
	Containers []Container
}

type Container struct {
	Name            string
	Image           string
	Vulnerabilities Vulnerabilities
}

type Vulnerabilities struct {
	Critical int
	High     int
	Medium   int
	Low      int
}
