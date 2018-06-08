// Package client implements a Kubernetes client-go auth plugin using Vault.
package client

import (
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/config"
	"github.com/pkg/errors"
	"io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1alpha1"
	"net/http"
	"os"
	"time"
)

const (
	reqEnv       = "KUBERNETES_EXEC_INFO"
	pathEnv      = "KUBE_VAULT_PATH"
	roleEnv      = "KUBE_VAULT_ROLE"
	cacheEnv     = "KUBE_VAULT_CACHE"
	pathDefault  = "kubernetes"
	expireBuffer = 1 * time.Second
	v1alpha1     = "client.authentication.k8s.io/v1alpha1"
)

// env holds all the inputs and outputs of the Kubernetes client-go exec auth plugin.
type env struct {
	Getenv func(string) string
	Stderr io.Writer
	Stdout io.Writer
	Stdin  io.Reader
	// For testing, a manually-specified Vault client.
	vaultClient *api.Client
}

// Run runs the auth plugin, using the process environment for input and output.
func Run() error {
	return runEnv(env{
		Getenv: os.Getenv,
		Stderr: os.Stderr,
		Stdout: os.Stdout,
		Stdin:  os.Stdin,
	})
}

// runEnv runs the auth plugin usnig the configured inputs and outputs (useful for testing).
func runEnv(e env) error {
	var req clientauthv1.ExecCredential
	rawReq := e.Getenv(reqEnv)
	err := json.Unmarshal([]byte(rawReq), &req)
	if err != nil {
		return errors.Wrap(err, "invalid exec credential input")
	}
	if req.APIVersion != v1alpha1 {
		return fmt.Errorf("unknown exec credential API version: %s", req.APIVersion)
	}

	path := e.Getenv(pathEnv)
	if path == "" {
		if req.Spec.Interactive {
			fmt.Fprintf(e.Stderr, "%s not set - prompting for Kubernetes backend mount path\n", pathEnv)
			fmt.Fprintf(e.Stderr, "path (empty for '%s'): ", pathDefault)
			fmt.Fscanln(e.Stdin, &path)
		}
		if path == "" {
			path = pathDefault
		}
	}

	role := e.Getenv(roleEnv)
	if role == "" {
		if req.Spec.Interactive {
			fmt.Fprintf(e.Stderr, "%s not set - prompting for Kubernetes backend role name\n", roleEnv)
			fmt.Fprint(e.Stderr, "role: ")
			fmt.Fscanln(e.Stdin, &role)
		}
		if role == "" {
			return fmt.Errorf("role name required - set %s or enter interactively", roleEnv)
		}
	}

	client := e.vaultClient
	if client == nil {
		if client, err = createClient(); err != nil {
			return errors.Wrap(err, "failed to create vault client")
		}
	}

	cache, err := loadCache(e.Getenv(cacheEnv))
	if err != nil {
		return errors.Wrap(err, "error loading token cache")
	}
	// TODO: Support lease renewals.
	entry := cache.Get(client.Address(), path, role)
	if req.Spec.Response != nil && req.Spec.Response.Code == http.StatusUnauthorized {
		// The previous returned credential was unauthorized. Clear it from the cache.
		cache.Delete(entry)
		if err := cache.WriteOut(); err != nil {
			return err
		}
		entry = nil
	}
	if entry != nil && time.Now().Before(entry.Expiration) {
		return writeResponse(e.Stdout, entry)
	}
	entry, err = fetchToken(client, path, role)
	if err != nil {
		return err
	}
	cache.Put(entry)
	if err := cache.WriteOut(); err != nil {
		return err
	}
	return writeResponse(e.Stdout, entry)
}

func fetchToken(client *api.Client, path, role string) (*cacheEntry, error) {
	if client.Token() == "" {
		return nil, errors.New("no Vault token found - do you need to `vault login`?")
	}
	tokenPath := fmt.Sprintf("%s/token/%s", path, role)
	secret, err := client.Logical().Read(tokenPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get Kubernetes token from Vault")
	}
	if secret == nil {
		return nil, fmt.Errorf(
			"no Vault value at %s - the Kubernetes backend may not be mounted at %s",
			tokenPath, path)
	}

	token, ok := secret.Data["token"].(string)
	if !ok {
		return nil, errors.New("could not parse Kubernetes token string from Vault response")
	}
	expiration := time.Now().Add(time.Duration(secret.LeaseDuration) * time.Second).Add(-expireBuffer)
	return &cacheEntry{
		Addr:       client.Address(),
		Path:       path,
		Role:       role,
		Token:      token,
		Expiration: expiration,
		Lease:      secret.LeaseID,
		Renewable:  secret.Renewable,
	}, nil
}

func writeResponse(w io.Writer, entry *cacheEntry) error {
	resp := &clientauthv1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ExecCredential",
			APIVersion: v1alpha1,
		},
		Status: &clientauthv1.ExecCredentialStatus{
			ExpirationTimestamp: &metav1.Time{Time: entry.Expiration},
			Token:               entry.Token,
		},
	}
	enc := json.NewEncoder(w)
	if err := enc.Encode(resp); err != nil {
		return errors.Wrap(err, "error writing response")
	}
	return nil
}

// TODO: Replace this: https://github.com/hashicorp/vault/issues/4688.
func createClient() (*api.Client, error) {
	cfg := api.DefaultConfig()
	if err := cfg.ReadEnvironment(); err != nil {
		return nil, errors.Wrap(err, "failed to read environment")
	}
	// Build the client
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create client")
	}
	// Get the token if it came in from the environment
	token := client.Token()

	// If we don't have a token, check the token helper
	if token == "" {
		helper, err := config.DefaultTokenHelper()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get token helper")
		}
		token, err = helper.Get()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get token from token helper")
		}
	}

	// Set the token
	if token != "" {
		client.SetToken(token)
	}
	return client, nil
}
