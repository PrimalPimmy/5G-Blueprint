package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	// // Create in-cluster config
	// config, err := rest.InClusterConfig()
	// if err != nil {
	// 	panic(err.Error())
	// }

	// var kubeconfig *string
	// if home := homedir.HomeDir(); home != "" {
	// 	kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "edge-kubeconfig"), "(optional) absolute path to the kubeconfig file")
	// } else {
	// 	kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	// }
	// flag.Parse()

	config, err := clientcmd.BuildConfigFromFlags("", "/home/ubuntu/.kube/edge-kubeconfig")
	if err != nil {
		panic(err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	// // List pods across all namespaces
	// pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	// if err != nil {
	// 	panic(err.Error())
	// }
	jsonPath := flag.String("config", "", "path to JSON config file")
	flag.Parse()

	// Check if file path is provided
	if *jsonPath == "" {
		fmt.Println("Please provide a JSON file path using -config flag")
		os.Exit(1)
	}

	// Read the file
	data, err := os.ReadFile(*jsonPath)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	var workloads []Workload
	if err := json.Unmarshal([]byte(data), &workloads); err != nil {
		panic(err)
	}

	for _, workload := range workloads {
		verifyWorkloadInCluster(clientset, workload)
		checkSensitiveDirs(config, workload.SensitiveLocations)
	}

}

type Workload struct {
	ComponentName      string   `json:"Component Name"`
	WorkloadNamespace  string   `json:"Workload Namespace"`
	WorkloadLabels     []string `json:"Workload Labels"`
	SensitiveLocations []string `json:"Sensitive Asset Locations"`
	VolumeMounts       []string `json:"Volume mounts"`
}

func verifyWorkloadInCluster(clientset *kubernetes.Clientset, workload Workload) error {
	// Check if namespace exists
	_, err := clientset.CoreV1().Namespaces().Get(context.TODO(), workload.WorkloadNamespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("namespace %s not found", workload.WorkloadNamespace)
	}

	// Create label selector from workload labels
	var labelSelector string
	for _, v := range workload.WorkloadLabels {
		if labelSelector != "" {
			labelSelector += ","
		}
		labelSelector += v
	}

	// Check if pods with these labels exist in the namespace
	pods, err := clientset.CoreV1().Pods(workload.WorkloadNamespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return fmt.Errorf("error checking pods: %v", err)
	}

	if len(pods.Items) == 0 {
		return fmt.Errorf("no pods found with labels %v in namespace %s", workload.WorkloadLabels, workload.WorkloadNamespace)
	}

	return nil
}

type FileMatch struct {
	Dir       string
	Action    string
	Recursive bool
}

func checkSensitiveDirs(config *rest.Config, sensitiveDirs []string) error {
	// Create in-cluster config

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create dynamic client: %w", err)
	}

	// Define KubeArmorPolicy GVR
	gvr := schema.GroupVersionResource{
		Group:    "security.kubearmor.com",
		Version:  "v1",
		Resource: "kubearmorpolicies",
	}

	// List all policies across all namespaces
	policies, err := dynamicClient.Resource(gvr).Namespace("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list policies: %w", err)
	}

	for _, policy := range policies.Items {
		spec := policy.Object["spec"].(map[string]interface{})

		if file, ok := spec["file"].(map[string]interface{}); ok {
			if dirs, ok := file["matchDirectories"].([]interface{}); ok {
				for _, dir := range dirs {
					dirMap := dir.(map[string]interface{})
					dirPath := dirMap["dir"].(string)
					action := dirMap["action"].(string)

					for _, sensitiveDir := range sensitiveDirs {
						if dirPath == sensitiveDir {
							fmt.Printf("Found sensitive dir in policy %s:\n  Path: %s\n  Action: %s\n",
								policy.GetName(), dirPath, action)
						}
					}
				}
			}
		}
	}
	return nil
}
