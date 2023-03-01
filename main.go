package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	var (
		kubeConfig string
		namespace  string
	)

	flag.StringVar(&kubeConfig, "kubeconfig", "~/.kube/config", "Kubeconfig file path (default \"~/.kube/config\"")
	flag.StringVar(&namespace, "namespace", "", "Scan images in a namespace (default all namespaces")
	flag.Parse()

	if strings.HasPrefix(kubeConfig, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatal(err)
		}
		kubeConfig = filepath.Join(homeDir, kubeConfig[2:])
	}

	log.Printf("kubeconfig file path: %s", kubeConfig)

	if _, err := os.Stat(kubeConfig); errors.Is(err, os.ErrNotExist) {
		log.Fatal(err)
	}

	// uses the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
	if err != nil {
		log.Fatal(err)
	}

	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	// access the API to list pods
	pods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), v1.ListOptions{})
	if err != nil {
		log.Fatal(err)
	}

	var images = make(map[string]string)
	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			if _, ok := images[container.Image]; !ok {
				images[container.Image] = container.Image
				log.Println(container.Image)
			}
		}
	}

	if err := os.MkdirAll("results", os.ModePerm); err != nil {
		log.Fatal(err)
	}

	criticalVuln := 0
	highVuln := 0
	mediumVuln := 0
	lowVuln := 0
	unspecifiedVuln := 0

	var wg sync.WaitGroup

	for _, image := range images {
		wg.Add(1)
		image := image
		go func() {
			defer wg.Done()

			// replace the matched non-alphanumeric characters with the underscore character
			outputFile := filepath.Join("results", regexp.MustCompile(`[^a-zA-Z-0-9]+`).ReplaceAllString(image, "_")+".sarif.json")
			cmd := exec.Command("docker", "scout", "cves", "--format", "sarif", "--only-fixed", "--output", outputFile, image)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
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
						log.Printf("Severity: %s", rule.Properties.CvssV3Severity)

						switch rule.Properties.CvssV3Severity {
						case "UNSPECIFIED":
							unspecifiedVuln += 1
						case "LOW":
							lowVuln += 1
						case "MEDIUM":
							mediumVuln += 1
						case "HIGH":
							highVuln += 1
						case "CRITICAL":
							criticalVuln += 1
						}
						break
					}
				}

			}
		}()
	}

	log.Println("Waiting for all goroutines to complete")
	wg.Wait()

	log.Printf("Total critical: %d", criticalVuln)
	log.Printf("Total high: %d", highVuln)
	log.Printf("Total medium: %d", mediumVuln)
	log.Printf("Total low: %d", lowVuln)
	log.Printf("Total unspecified: %d", unspecifiedVuln)
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

//
//type SarifReport struct {
//	Runs []struct {
//		Results []struct {
//			RuleID    string `json:"ruleId"`
//			RuleIndex int    `json:"ruleIndex"`
//			Kind      string `json:"kind"`
//			Level     string `json:"level"`
//			Message   struct {
//				Text string `json:"text"`
//			} `json:"message"`
//			Locations []struct {
//				LogicalLocations []struct {
//					Name string `json:"name,omitempty"`
//					FQN  string `json:"fullyQualifiedName"`
//					Kind string `json:"kind,omitempty"`
//				} `json:"logicalLocations"`
//			} `json:"locations"`
//		} `json:"results"`
//	} `json:"runs"`
//}
