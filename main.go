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
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/hashicorp/go-version"
	"github.com/jedib0t/go-pretty/v6/table"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// dockerDesktopMinVersion is the first version of Docker Desktop that ships the "docker scout" CLI plugin.
	dockerDesktopMinVersion = "4.17.0"
	// resultsDir is the host directory where the analysis SARIF files will be stored
	resultsDir = "results"
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

	if _, err := os.Stat(resultsDir); !errors.Is(err, os.ErrNotExist) {
		_ = os.RemoveAll(resultsDir)
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

	var hubUser, hubPassword string
	canUseDockerScoutCLI := canUseDockerScoutCLI()
	if canUseDockerScoutCLI {
		log.Printf("Will be using the docker scout CLI plugin that is shipped with Docker Desktop to analyze images")
	} else {
		log.Println("Docker Desktop 4.17 or higher is not detected in the system, will be using the image \"docker/scout-cli\" to analyze the images running in the Kubernetes cluster.")
		log.Println("Note that the analysis will take longer as we'll be running docker scout in a container instead of using the CLI that comes with Docker Desktop 4.17 or higher.")
		log.Println("For this reason make sure to provide \"DOCKER_SCOUT_HUB_USER\" and \"DOCKER_SCOUT_HUB_PASSWORD\" as environment variables to provide such values within the container where docker scout runs.")

		hubUser = os.Getenv("DOCKER_SCOUT_HUB_USER")
		if hubUser == "" {
			log.Fatal("Environment variable DOCKER_SCOUT_HUB_USER is not set.")
		}

		hubPassword = os.Getenv("DOCKER_SCOUT_HUB_PASSWORD")
		if hubPassword == "" {
			log.Fatal("Environment variable DOCKER_SCOUT_HUB_PASSWORD is not set.")
		}
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

	if err := os.MkdirAll(resultsDir, os.ModePerm); err != nil {
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

		for i, c := range pod.Spec.Containers {
			wg.Add(1)

			i := i
			c := c

			item.Pod.Containers = append(item.Pod.Containers, Container{
				Name:  c.Name,
				Image: c.Image,
			})

			go func() {
				defer wg.Done()

				var outDir string

				var cmd *exec.Cmd
				var args []string
				if canUseDockerScoutCLI {
					args = []string{"scout", "cves"}
					outDir = resultsDir
				} else {
					wd, err := os.Getwd()
					if err != nil {
						log.Fatal(err)
					}

					// Run the containerized version of docker scout using the docker/scout-cli image
					args = []string{
						"run",
						"--rm",
						"-e", fmt.Sprintf("DOCKER_SCOUT_HUB_USER=%s", hubUser),
						"-e", fmt.Sprintf("DOCKER_SCOUT_HUB_PASSWORD=%s", hubPassword),
						"-v", fmt.Sprintf("%s/%s:/tmp", wd, resultsDir),
						"docker/scout-cli",
						"cves"}

					outDir = "/tmp"
				}

				// replace the matched non-alphanumeric characters with the underscore character
				reportFilename := regexp.MustCompile(`[^a-zA-Z-0-9]+`).ReplaceAllString(c.Image, "_") + ".sarif.json"
				outputFile := filepath.Join(outDir, reportFilename)
				args = append(args, scoutArgs...)
				args = append(args, "--format", "sarif", "--output", outputFile, c.Image)

				cmd = exec.Command("docker", args...)
				if err := cmd.Run(); err != nil {
					log.Fatal(err)
				}

				b, err := os.ReadFile(filepath.Join(resultsDir, reportFilename))
				if err != nil {
					log.Fatal(err)
				}
				var report SarifReport

				if err := json.Unmarshal(b, &report); err != nil {
					log.Fatal(err)
				}

				for _, result := range report.Runs[0].Results {
					switch {
					case strings.Contains(result.Message.Text, ": LOW"):
						item.Pod.Containers[i].Vulnerabilities.Low += 1
						lowVuln += 1
					case strings.Contains(result.Message.Text, ": MEDIUM"):
						item.Pod.Containers[i].Vulnerabilities.Medium += 1
						mediumVuln += 1
					case strings.Contains(result.Message.Text, ": HIGH"):
						item.Pod.Containers[i].Vulnerabilities.High += 1
						highVuln += 1
					case strings.Contains(result.Message.Text, ": CRITICAL"):
						item.Pod.Containers[i].Vulnerabilities.Critical += 1
						criticalVuln += 1
					}
				}
			}()
		}

		items = append(items, item)
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
		{Number: 2, AutoMerge: true},
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

// canUseDockerScoutCLI returns whether the user has Docker Desktop installed and comes with Docker Scout (4.17 or higher).
func canUseDockerScoutCLI() bool {
	canUse := false

	b, err := exec.Command("docker", "version").CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}

	var re = regexp.MustCompile(`(?m)Server: Docker Desktop (?P<version>.*) `)
	for _, line := range strings.Split(string(b), "\n") {
		if len(re.FindStringSubmatch(line)) == 2 {
			detectedVersion, err := version.NewVersion(re.FindStringSubmatch(line)[1])
			if err != nil {
				log.Fatal(err)
			}

			minVersion, _ := version.NewVersion(dockerDesktopMinVersion)
			if detectedVersion.GreaterThanOrEqual(minVersion) {
				log.Printf("Docker Desktop version %s is greater or equal than %s", detectedVersion, minVersion)
				canUse = true
				break
			}

		}
	}

	return canUse
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
