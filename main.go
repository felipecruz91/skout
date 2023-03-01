package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

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

	for _, image := range images {
		outputFile := filepath.Join("results", regexp.MustCompile(`[^a-zA-Z	0-9]+`).ReplaceAllString(image, "_")+".sarif.json")
		cmd := exec.Command("docker", "scout", "cves", "--format", "sarif", "--only-fixed", "--output", outputFile, image)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Fatal(err)
		}
	}

}
