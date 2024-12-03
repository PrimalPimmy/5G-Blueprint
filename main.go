package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type RiskList struct {
	RiskID          string
	RiskDescription string
	Checkpoints     []string
	Assets          []string
	Exploitability  string
	Severity        string
	RemediationTime string
	Solutions       string
	References      []string
}

type RiskConfig struct {
	RiskID          string     `yaml:"risk_id"`
	RiskDescription string     `yaml:"risk_description"`
	Severity        string     `yaml:"severity"`
	Checkpoints     Checkpoint `yaml:"checkpoints"`
}

type Checkpoint struct {
	TLS                      bool `yaml:"TLS"`
	SensitiveAssetProtection bool `yaml:"sensitive_asset_protection"`
	NetworkPolicy            bool `yaml:"network_policy"`
}

type Risks struct {
	Risks []RiskConfig `yaml:"risks"`
}

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
	var risk []RiskList
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Read YAML config
		f, err := os.ReadFile("risk_config.yaml")
		if err != nil {
			log.Fatal(err)
		}

		var risks Risks
		err = yaml.Unmarshal(f, &risks)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("YAML FILE: ", risks)

		for _, workload := range workloads {
			verifyWorkloadInCluster(clientset, workload)
			checkSensitiveDirs(workload.WorkloadNamespace, config, workload.SensitiveLocations)
			for _, r := range risks.Risks {
				// Create risk struct with config data
				risk = append(risk, RiskList{
					RiskID:          r.RiskID,
					RiskDescription: r.RiskDescription,
					Severity:        r.Severity,
					Checkpoints:     []string{"Is TLS Enabled?", "Least Permissive Policies?"},
					Assets:          workload.SensitiveLocations,
					Exploitability:  "High",
					RemediationTime: "High",
					Solutions:       "Test solutions",
					References:      []string{"Reference 1", "Reference 2"},
				})
			}

		}

		tmpl := `
		<!DOCTYPE html>
<html>
<head>
    <style>
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
    </style>
</head>
<body>
    <table>
        <thead>
            <tr>
                <th>Risk ID</th>
                <th>Risk Description</th>
                <th>Checkpoints</th>
                <th>Assets</th>
                <th>Exploitability</th>
                <th>Severity</th>
                <th>Est Remediation Time</th>
                <th>Solutions</th>
                <th>References</th>
            </tr>
        </thead>
        <tbody>
            {{range $index, $element := .}}
            <tr>
                {{if and (gt $index 0) (eq .RiskID (index $ (sub $index 1)).RiskID)}}
                    <!-- Skip td if same as previous -->
                {{else}}
                    <td rowspan="{{countSameValues $ $index .RiskID}}">{{.RiskID}}</td>
                {{end}}
                <td>{{.RiskDescription}}</td>
                <td>{{.Checkpoints}}</td>
                <td>{{.Assets}}</td>
                <td>{{.Exploitability}}</td>
                <td>{{.Severity}}</td>
                <td>{{.RemediationTime}}</td>
                <td>{{.Solutions}}</td>
                <td>{{.References}}</td>
            </tr>
            {{end}}
        </tbody>
    </table>
</body>
</html>
`
		t := template.Must(template.New("table").Parse(tmpl))

		t.Execute(w, risk)
	})

	http.ListenAndServe(":8080", nil)

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

func checkSensitiveDirs(namespace string, config *rest.Config, sensitiveDirs []string) error {
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
	policies, err := dynamicClient.Resource(gvr).Namespace(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list policies: %w", err)
	}

	for _, policy := range policies.Items {
		spec, ok := policy.Object["spec"].(map[string]interface{})
		if !ok {
			continue
		}

		file, ok := spec["file"].(map[string]interface{})
		if !ok {
			continue
		}

		matchDirs, ok := file["matchDirectories"].([]interface{})
		if !ok {
			continue
		}

		for _, dir := range matchDirs {
			dirMap, ok := dir.(map[string]interface{})
			if !ok {
				continue
			}

			dirPath, ok := dirMap["dir"].(string)
			if !ok {
				continue
			}

			action, ok := dirMap["action"].(string)
			if !ok {
				continue
			}

			for _, sensitiveDir := range sensitiveDirs {
				if dirPath == sensitiveDir {
					fmt.Printf("Found sensitive dir in policy %s:\n  Path: %s\n  Action: %s\n",
						policy.GetName(), dirPath, action)
				}
			}
		}

		// Check matchPaths
		if matchPaths, ok := file["matchPaths"].([]interface{}); ok {
			for _, path := range matchPaths {
				pathMap, ok := path.(map[string]interface{})
				if !ok {
					continue
				}

				filePath, ok := pathMap["path"].(string)
				if !ok {
					continue
				}

				action, ok := pathMap["action"].(string)
				if !ok {
					continue
				}

				// readOnly, _ := pathMap["readOnly"].(bool)

				for _, sensitiveDir := range sensitiveDirs {
					if filePath == sensitiveDir {
						fmt.Printf("Found sensitive path in policy %s:\n  Path: %s\n  Action: %s\n",
							policy.GetName(), filePath, action)
					}
				}
			}
		}

	}
	return nil
}
