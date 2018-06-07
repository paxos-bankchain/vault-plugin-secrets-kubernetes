package client

import (
	"bytes"
	"encoding/json"
	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/vault"
	"github.com/paxos-bankchain/vault-plugin-secrets-kubernetes/pkg/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1alpha1"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"
	"time"
)

func envFunc(m map[string]string) func(string) string {
	return func(k string) string {
		return m[k]
	}
}

const (
	noneToken = "magical string indicating test case should strip Vault token"
)

func getCluster(t *testing.T) *vault.TestCluster {
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"kubernetes": backend.Factory,
		},
		// Quiet down the Vault cluster logs.
		Logger: hclog.New(&hclog.LoggerOptions{
			Level: hclog.Error,
		}),
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	client := cluster.Cores[0].Client
	err := client.Sys().Mount("kubernetes", &api.MountInput{
		Type: "kubernetes",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "16h",
			MaxLeaseTTL:     "32h",
		},
	})
	require.NoError(t, err)
	return cluster
}

type testCase struct {
	// path is the value of KUBE_VAULT_PATH during execution.
	path string
	// role is the value of KUBE_VAULT_ROLE during execution.
	role string
	// interactive is whether this is an interactive execution.
	interactive bool
	// stdin is the line-by-line input for interactive execution.
	stdin []string
	// cache is the contents of the cache before execution.
	cache []*cacheEntry
	// vaultToken overrides the token used by the provided Vault client.
	vaultToken string
	// afterDenial indicates this execution follows a denial of earlier credentials.
	afterDenial bool
	// errLike is a regexp indicating execution should fail with a matching error.
	errLike string
}

func (c testCase) run(t *testing.T, vaultClient *api.Client) {
	cacheDir, err := ioutil.TempDir("", "")
	defer os.RemoveAll(cacheDir)
	cacheFile := path.Join(cacheDir, "token-cache")

	// Pre-load the cache with any specified state.
	if len(c.cache) != 0 {
		assert.NoError(t, (&tokenCache{file: cacheFile, entries: c.cache}).WriteOut())
	}

	if c.vaultToken != "" {
		vaultClient, err = vaultClient.Clone()
		require.NoError(t, err)
		if c.vaultToken == noneToken {
			vaultClient.ClearToken()
		} else {
			vaultClient.SetToken(c.vaultToken)
		}
	}

	req := &clientauthv1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ExecCredential",
			APIVersion: v1alpha1,
		},
		Spec: clientauthv1.ExecCredentialSpec{
			Interactive: c.interactive,
		},
	}
	if c.afterDenial {
		req.Spec.Response = &clientauthv1.Response{
			Code: http.StatusUnauthorized,
		}
	}
	reqBytes, err := json.Marshal(req)
	require.NoError(t, err)

	e := env{
		Getenv: envFunc(map[string]string{
			pathEnv:  c.path,
			roleEnv:  c.role,
			reqEnv:   string(reqBytes),
			cacheEnv: cacheFile,
		}),
		Stderr:      &bytes.Buffer{},
		Stdout:      &bytes.Buffer{},
		Stdin:       strings.NewReader(strings.Join(c.stdin, "\n")),
		vaultClient: vaultClient,
	}
	err = runEnv(e)
	if c.errLike != "" {
		if assert.Error(t, err) {
			assert.Regexp(t, c.errLike, err.Error())
		}
		_, err := loadCache(cacheFile)
		require.NoError(t, err, "errors should not corrupt token cache")
		return
	}
	require.NoError(t, err)
	var resp clientauthv1.ExecCredential
	err = json.Unmarshal(e.Stdout.(*bytes.Buffer).Bytes(), &resp)
	assert.NoError(t, err, "plugin response should parse")
	if assert.NotNil(t, resp.TypeMeta, "plugin response should have meta") {
		assert.Equal(t, "ExecCredential", resp.TypeMeta.Kind, "plugin response should have kind")
		assert.Equal(t, v1alpha1, resp.TypeMeta.APIVersion, "plugin response should have API version")
	}
	if assert.NotNil(t, resp.Status, "plugin response should have status") {
		assert.NotEmpty(t, resp.Status.Token, "plugin response should have token")
		assert.NotNil(t, resp.Status.ExpirationTimestamp, "plugin response should have expiration")
		c.assertMatchingEntry(t, resp.Status, cacheFile, vaultClient.Address())
	}
}

func (c testCase) assertMatchingEntry(t *testing.T, respStatus *clientauthv1.ExecCredentialStatus, cacheFile, addr string) {
	cache, err := loadCache(cacheFile)
	if assert.NoError(t, err, "cache should not be corrupted") {
		for _, e := range cache.entries {
			if e.Addr == addr &&
				(e.Path == c.path || c.path == "") &&
				(e.Role == c.role || c.role == "") &&
				e.Token == respStatus.Token &&
				e.Expiration.Truncate(time.Second).Equal(respStatus.ExpirationTimestamp.Time) {
				return
			}
		}
		entries := spew.Sdump(cache.entries)
		expected := spew.Sdump(&cacheEntry{
			Addr:       addr,
			Path:       c.path,
			Role:       c.role,
			Token:      respStatus.Token,
			Expiration: respStatus.ExpirationTimestamp.Time})
		assert.Fail(t, "no matching entry found",
			"expected %s to contain entry matching %s",
			entries, expected)
	}
}

func TestRun(t *testing.T) {
	cluster := getCluster(t)
	defer cluster.Cleanup()

	vaultClient := cluster.Cores[0].Client
	_, err := vaultClient.Logical().Write(
		"kubernetes/roles/role1", map[string]interface{}{})
	require.NoError(t, err)

	cases := map[string]testCase{
		"ErrNoRole": {
			errLike: "role name required",
		},
		"ErrNoRoleInteractive": {
			interactive: true,
			stdin:       []string{"", ""},
			errLike:     "role name required",
		},
		"ErrBadPath": {
			path:    "notmounted",
			role:    "role1",
			errLike: "no Vault value at notmounted/token/role1",
		},
		"ErrBadRole": {
			role:    "notarole",
			errLike: "failed to get Kubernetes token",
		},
		"ErrNoToken": {
			role:       "role1",
			errLike:    "no Vault token found",
			vaultToken: noneToken,
		},
		"ErrForbidden": {
			role:       "role1",
			errLike:    "failed to get Kubernetes token",
			vaultToken: "invalid-token",
		},
		"NonInteractive": {
			path: "kubernetes",
			role: "role1",
		},
		"NonInteractive_PathDefault": {
			role: "role1",
		},
		"Interactive_PathEnvRoleEnv": {
			interactive: true,
			path:        "kubernetes",
			role:        "role1",
		},
		"Interactive_PathEnvRoleInteractive": {
			interactive: true,
			path:        "kubernetes",
			stdin:       []string{"role1"},
		},
		"Interactive_PathDefaultRoleInteractive": {
			interactive: true,
			stdin:       []string{"", "role1"},
		},
		"Cached": {
			role:       "role1",
			vaultToken: noneToken,
			cache: []*cacheEntry{
				{
					Addr:       vaultClient.Address(),
					Path:       "kubernetes",
					Role:       "role1",
					Token:      "kube-auth-token",
					Expiration: time.Now().Add(5 * time.Minute).Truncate(time.Second),
				},
			},
		},
		"ErrCachedExpired": {
			role:       "role1",
			vaultToken: noneToken,
			cache: []*cacheEntry{
				{
					Addr:       vaultClient.Address(),
					Path:       "kubernetes",
					Role:       "role1",
					Token:      "kube-auth-token",
					Expiration: time.Now().Add(-5 * time.Minute).Truncate(time.Second),
				},
			},
			errLike: "no Vault token found",
		},
		"CachedExpired": {
			role: "role1",
			cache: []*cacheEntry{
				{
					Addr:       vaultClient.Address(),
					Path:       "kubernetes",
					Role:       "role1",
					Token:      "kube-auth-token",
					Expiration: time.Now().Add(-5 * time.Minute).Truncate(time.Second),
				},
			},
		},
		"ErrCachedRevoked": {
			role:        "role1",
			vaultToken:  "forbidden-token",
			afterDenial: true,
			cache: []*cacheEntry{
				{
					Addr:       vaultClient.Address(),
					Path:       "kubernetes",
					Role:       "role1",
					Token:      "kube-auth-token",
					Expiration: time.Now().Add(5 * time.Minute).Truncate(time.Second),
				},
			},
			errLike: "failed to get Kubernetes token",
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			c.run(t, vaultClient)
		})
	}
}
