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
	"strings"

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
	Checkpoints     []Checkpoint
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
	Satisfied   bool
	Description string
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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Read YAML config
		f, err := os.ReadFile("risk_config.yaml")
		if err != nil {
			log.Fatal(err)
		}
		var risk []RiskList

		var risks Risks
		err = yaml.Unmarshal(f, &risks)
		if err != nil {
			log.Fatal(err)
		}

		for _, workload := range workloads {
			verifyWorkloadInCluster(clientset, workload)
			var check []Checkpoint
			Asset, isThere, _ := checkSensitiveDirs(workload.WorkloadNamespace, config, workload.SensitiveLocations)
			fmt.Println("TEST", Asset)
			for _, r := range risks.Risks {
				if isThere {
					check = []Checkpoint{
						{Satisfied: true, Description: "Least Permessive Policies for Sensitive Assets?"},
					}

				} else {
					check = []Checkpoint{
						{Satisfied: false, Description: "Least Permessive Policies for Sensitive Assets?"},
					}

				}
				// Create risk struct with config data
				risk = append(risk, RiskList{
					RiskID:          r.RiskID,
					RiskDescription: r.RiskDescription,
					Severity:        r.Severity,
					Checkpoints:     check,
					Assets:          workload.SensitiveLocations,
					Exploitability:  "High",
					RemediationTime: "High",
					Solutions:       "Test solutions",
					References:      []string{"Reference 1", "Reference 2"},
				})
			}

		}

		MapRisks := mergeResponses(risk)

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
        .tick {
            color: green;
        }
        .cross {
            color: red;
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
            {{range .}}
            <tr>
                <td>{{.RiskID}}</td>
                <td>{{.RiskDescription}}</td>
                <td>
                    {{range .Checkpoints}}
                        <div>
                            {{if .Satisfied}}
                                <span class="tick">✓</span>
                            {{else}}
                                <span class="cross">✗</span>
                            {{end}}
                            {{.Description}}
                        </div>
                    {{end}}
                </td>
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

		for _, v := range MapRisks {
			t := template.Must(template.New("table").Parse(tmpl))
			t.Execute(w, v)
			break
		}

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

func checkSensitiveDirs(namespace string, config *rest.Config, sensitiveDirs []string) ([]string, bool, error) {
	// Create in-cluster config
	var Assets []string
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create dynamic client: %w", err)
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
		return nil, false, fmt.Errorf("failed to list policies: %w", err)
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
					fmt.Printf("Found sensitive asset in policy %s:\n  Path: %s\n  Action: %s\n",
						policy.GetName(), dirPath, action)
					Assets = append(Assets, dirPath)
					// return dirPath, nil
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
						fmt.Printf("Found sensitive asset in policy %s:\n  Path: %s\n  Action: %s\n",
							policy.GetName(), filePath, action)
						Assets = append(Assets, filePath)

					}
				}
			}
		}

	}
	return Assets, true, nil
}

func mergeResponses(risks []RiskList) map[string][]RiskList {
	merged := make(map[string][]RiskList)

	for _, response := range risks {
		key := strings.Join(response.Assets, "\n")
		merged[key] = append(merged[key], response)
	}

	return merged
}
