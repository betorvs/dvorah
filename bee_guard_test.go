package dvorah_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/support/kind"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

var (
	testenv   env.Environment
	namespace string
	version   string
)

func TestMain(m *testing.M) {
	testenv = env.New()
	kindClusterName := envconf.RandomName("e2e-test", 16)
	namespace = "dvorah"
	if v := os.Getenv("VERSION"); v != "" {
		version = v
	} else {
		version = "1.0.0"
	}

	// pre-test setup of kind cluster
	testenv.Setup(
		envfuncs.CreateCluster(kind.NewProvider(), kindClusterName),
		envfuncs.CreateNamespace(namespace),
		// you can have multiple LoadDockerImageToCluster to load multiple images
		envfuncs.LoadDockerImageToCluster(kindClusterName, fmt.Sprintf("betorvs/dvorah:%s", version)),
	)

	// post-test teardown kind cluster
	testenv.Finish(
		envfuncs.DeleteNamespace(namespace),
		envfuncs.DestroyCluster(kindClusterName),
	)
	os.Exit(testenv.Run(m))
}

func TestExample(t *testing.T) {
	// test code here
	t.Run("Test Example", func(t *testing.T) {
		t.Logf("Running test with version: %s", version)
		f := features.New("install applications").Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			cmd := exec.CommandContext(ctx, "/bin/bash", "./scripts/certs.sh")
			logCreds, err := cmd.Output()
			if err != nil {
				t.Logf("output from dvorah creds: %v", string(logCreds))
				t.Fatalf("Failed to generate tls certificates: %v", err)
			}
			t.Logf("exit code from dvorah creds: %v", cmd.ProcessState.ExitCode())
			cert := exec.CommandContext(ctx, "/bin/bash", "./scripts/read-tls.sh")
			caBundle, err := cert.Output()
			if err != nil {
				t.Fatalf("Failed to read tls certificate: %v", err)
			}
			helmMgr := helm.New(cfg.KubeconfigFile())
			err = helmMgr.RunInstall(helm.WithName("dvorah"), helm.WithNamespace(namespace), helm.WithReleaseName("dvorah"), helm.WithChart("charts/dvorah"), helm.WithArgs("--set", "image.repository=betorvs/dvorah", "--set", "image.tag="+version, "--set", "args.policyConfig=true", "--set", "env.enabled=true", "--set", "validatingWebhook.caBundle="+string(caBundle)))
			// err = helmMgr.RunInstall(helm.WithName("auror"), helm.WithNamespace(namespace), helm.WithReleaseName("auror"), helm.WithChart("charts/auror"), helm.WithArgs("-f", "values.kind.yaml", "--set", "image.tag="+version, "--set", "mutatingWebhook.caBundle="+string(caBundle)))
			if err != nil {
				t.Fatalf("Failed to install dvorah helm chart: %v", err)
			}
			// wait
			time.Sleep(15 * time.Second)
			return ctx
		}).Assess("checking pod", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// test application running on kind
			podList := corev1.PodList{}
			err := cfg.Client().Resources(namespace).List(ctx, &podList)
			if err != nil {
				t.Fatalf("Error listing pods: %v", err)
			}
			podName := ""
			for _, pod := range podList.Items {
				if strings.HasPrefix(pod.Name, "dvorah") {
					t.Logf("Found pod %v with status %v", pod.Name, pod.Status.Phase)
					podName = pod.Name
					break
				}
			}

			if podName == "" {
				t.Fatalf("Failed to find pod with name prefix dvorah")
			}
			var stdout, stderr bytes.Buffer
			command := []string{"/bin/bee"}
			t.Logf("Running command: %v", command)
			err = cfg.Client().Resources().ExecInPod(ctx, namespace, podName, "dvorah", command, &stdout, &stderr)
			if err != nil {
				time.Sleep(30 * time.Second)
				t.Fatalf("Error running command in pod: %v", err)
			}
			t.Logf("stdout: %v", stdout.String())
			if strings.Contains(stdout.String(), "answered http code 200") {
				t.Logf("Command answered http code 200")
			} else {
				t.Fatalf("Command did not answered http code 200")
			}
			// use podName here to run commands if wanted
			t.Logf("Checking pod %v", podName)

			return ctx
		}).Teardown(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			helmMgr := helm.New(cfg.KubeconfigFile())
			err := helmMgr.RunUninstall(helm.WithName("dvorah"), helm.WithNamespace(namespace))
			if err != nil {
				t.Fatalf("Failed to uninstall dvorah helm chart: %v", err)
			}
			return ctx
		}).Feature()
		testenv.Test(t, f)
	})

}
