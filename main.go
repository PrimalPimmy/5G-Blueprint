package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/olekukonko/tablewriter"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func main() {
	// // Create in-cluster config
	// config, err := rest.InClusterConfig()
	// if err != nil {
	// 	panic(err.Error())
	// }

	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "edge-kubeconfig"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
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

	// Your JSON data
	jsonData := `[
	{
		"Component Name": "CU (UserPlane)",
		"Workload Namespace": "oai-ran-cuup",
		"Workload Labels": {"app.kubernetes.io/name": "oai-gnb-cu-up"},
		"Sensitive Asset Locations": ["/opt/oai-gnb/etc/gnb.conf","/opt/oai-gnb/bin/nr-cuup", "/run/secrets/kubernetes.io/serviceaccount/"],
		"Volume mounts": ["/opt/oai-gnb/etc/gnb.conf"]
	}
]`

	var workloads []Workload
	if err := json.Unmarshal([]byte(jsonData), &workloads); err != nil {
		panic(err)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Component Name", "Workload Namespace", "Workload Labels"})

	// Verify each workload
	for _, workload := range workloads {
		if err := verifyWorkloadInCluster(clientset, workload); err != nil {
			fmt.Printf("Workload verification failed: %v\n", err)
			continue
		}
		fmt.Printf("Workload found: %s in namespace %s with labels %v\n",
			workload.ComponentName,
			workload.WorkloadNamespace,
			workload.WorkloadLabels)
		for k, v := range workload.WorkloadLabels {
			table.Append([]string{workload.ComponentName, workload.WorkloadNamespace, k + "=" + v})
		}
		table.SetAutoMergeCells(true)

	}

	table.Render()
}

type Workload struct {
	ComponentName      string            `json:"Component Name"`
	WorkloadNamespace  string            `json:"Workload Namespace"`
	WorkloadLabels     map[string]string `json:"Workload Labels"`
	SensitiveLocations []string          `json:"Sensitive Asset Locations"`
	VolumeMounts       []string          `json:"Volume mounts"`
}

func verifyWorkloadInCluster(clientset *kubernetes.Clientset, workload Workload) error {
	// Check if namespace exists
	_, err := clientset.CoreV1().Namespaces().Get(context.TODO(), workload.WorkloadNamespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("namespace %s not found", workload.WorkloadNamespace)
	}

	// Create label selector from workload labels
	var labelSelector string
	for k, v := range workload.WorkloadLabels {
		if labelSelector != "" {
			labelSelector += ","
		}
		labelSelector += fmt.Sprintf("%s=%s", k, v)
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
