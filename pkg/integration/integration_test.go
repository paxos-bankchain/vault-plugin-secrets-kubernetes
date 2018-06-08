// Package integration_test does end-to-end testing of Kubernetes auth flows.
package integration_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/credential/userpass"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/vault"
	"github.com/mitchellh/mapstructure"
	"github.com/paxos-bankchain/vault-plugin-secrets-kubernetes/pkg/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	kubeApi "k8s.io/client-go/tools/clientcmd/api"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"
)

const (
	kubeAddrEnv        = "KUBE_ADDR"
	kubeContextEnv     = "KUBE_CONTEXT"
	kubeAuthVersionEnv = "KUBE_AUTH_VERSION"
	kubeTargetPortEnv  = "KUBE_TARGET_PORT"
)

var (
	insecureTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
)

func apiVersion(t *testing.T) string {
	v := os.Getenv(kubeAuthVersionEnv)
	switch v {
	case "", "v1":
		return "v1"
	case "v1beta1":
		return "v1beta1"
	default:
		t.Fatalf(
			"Unrecognized Kubernetes authentication.k8s.io API version in %s: %s",
			kubeAuthVersionEnv, v)
		panic("unreachable")
	}
}

// reviewer sends token review requests either to Vault or to Kubernetes.
// We make use of the "tokenreviews" endpoint exposed by Kubernetes to perform
// end-to-end checks of authentication decisions using vault-issued webhook tokens
// and the user information passed to Kubernetes on successful authentication.
// https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.10/#create-597
// Conveniently, this endpoint accepts the same input as the "tokenreviews"
// endpoint we must expose from Vault, meaning we can play the same requests
// against both for verification.
type reviewer interface {
	assertAllowed(t *testing.T, token string, expect expectedAllow) *authv1.UserInfo
	assertDenied(t *testing.T, token string)
	awaitDenied(t *testing.T, token string, expectedTime time.Time)
}

// reviewToken posts the given token for review to the given Vault or Kubernetes URL.
func reviewToken(t *testing.T, url, token, bearer string) (int, authv1.TokenReviewStatus, error) {
	buf, err := json.Marshal(
		&authv1.TokenReview{
			TypeMeta: metav1.TypeMeta{
				Kind:       "TokenReview",
				APIVersion: "authentication.k8s.io/" + apiVersion(t),
			},
			Spec: authv1.TokenReviewSpec{
				Token: token,
			},
		})
	require.NoError(t, err, "err encoding json")
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(buf))
	require.NoError(t, err, "err creating http request")
	req.Header.Add("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Add("Authorization", "Bearer "+bearer)
	}
	// For test simplicity, we don't enforce TLS checks.
	client := &http.Client{Transport: insecureTransport}
	resp, err := client.Do(req)

	require.NoError(t, err, "err making http request")
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	var respReview authv1.TokenReview
	decodeErr := json.Unmarshal(body, &respReview)
	return resp.StatusCode, respReview.Status, decodeErr
}

func awaitDenied(t *testing.T, isDenied func() bool, expectedTime time.Time, tolerance time.Duration) {
	stopTime := expectedTime.Add(tolerance)
	for {
		now := time.Now()
		if isDenied() {
			if now.Before(expectedTime) {
				t.Errorf("token denied %s before expected time %s", expectedTime.Sub(now), expectedTime)
			} else {
				t.Logf("token denied %s after expected time %s (tolerance %s)", now.Sub(expectedTime), expectedTime, tolerance)
			}
			return
		}
		if time.Now().After(stopTime) {
			t.Errorf("token was not denied at time %s (tolerance %s)", expectedTime, tolerance)
			return
		}
		time.Sleep(1 * time.Second)
	}
}

// kubeReviewer posts TokenReview requests to Kubernetes.
type kubeReviewer struct{}

func (r kubeReviewer) url(t *testing.T) string {
	kubeAddr := os.Getenv(kubeAddrEnv)
	if kubeAddr == "" {
		t.Skipf("%s must be set for integration tests", kubeAddrEnv)
	}
	return fmt.Sprintf("%s/apis/authentication.k8s.io/%s/tokenreviews",
		kubeAddr, apiVersion(t))
}

func (r kubeReviewer) assertAllowed(t *testing.T, token string, expect expectedAllow) *authv1.UserInfo {
	// Kubernetes adds the "system:authenticated" group to all authenticated users.
	expect.groups = append(expect.groups, "system:authenticated")
	code, status, decodeErr := reviewToken(t, r.url(t), token, token)
	expect.Assert(t, code, status, decodeErr)
	return &status.User
}

func (r kubeReviewer) assertDenied(t *testing.T, token string) {
	code, status, decodeErr := reviewToken(t, r.url(t), token, token)
	assert.Equal(t, http.StatusUnauthorized, code, "resp should have http status code UNAUTHORIZED")
	assert.Error(t, decodeErr, "resp should not parse to TokenReviewStatus")
	assert.Equal(t, authv1.TokenReviewStatus{}, status, "TokenReviewStatus should be empty")
}

func (r kubeReviewer) awaitDenied(t *testing.T, token string, expectedTime time.Time) {
	isDenied := func() bool {
		code, _, _ := reviewToken(t, r.url(t), token, token)
		return code == http.StatusUnauthorized
	}
	awaitDenied(t, isDenied, expectedTime, 15*time.Second)
}

// vaultReviewer posts TokenReview requests to Vault.
type vaultReviewer struct {
	url string
}

func (r vaultReviewer) assertAllowed(t *testing.T, token string, expect expectedAllow) *authv1.UserInfo {
	code, status, decodeErr := reviewToken(t, r.url, token, token)
	expect.Assert(t, code, status, decodeErr)
	return &status.User
}

func (r vaultReviewer) assertDenied(t *testing.T, token string) {
	code, status, decodeErr := reviewToken(t, r.url, token, "")
	assert.Equal(t, http.StatusCreated, code, "resp should have http status code CREATED")
	require.NoError(t, decodeErr, "resp should parse into TokenReviewStatus")
	assert.Equal(t, false, status.Authenticated, "user should not be authenticated")
	assert.Equal(t, authv1.UserInfo{}, status.User, "userinfo should be empty")
}

func (r vaultReviewer) awaitDenied(t *testing.T, token string, expectedTime time.Time) {
	isDenied := func() bool {
		_, status, _ := reviewToken(t, r.url, token, "")
		return !status.Authenticated
	}
	awaitDenied(t, isDenied, expectedTime, 1*time.Second)
}

type expectedAllow struct {
	uid          string
	usernameLike string
	groups       []string
	extra        backend.Extra
}

func (e *expectedAllow) Assert(t *testing.T, code int, status authv1.TokenReviewStatus, decodeErr error) {
	assert.NoError(t, decodeErr)
	assert.Equal(t, true, status.Authenticated, "user should be authenticated")
	assert.Equal(t, http.StatusCreated, code, "resp should have http status code CREATED")
	if e.uid == "" {
		assert.NotEmpty(t, status.User.UID, "user should have uid")
	} else {
		assert.Equal(t, e.uid, status.User.UID, "user should have uid")
	}
	assert.Regexp(t, e.usernameLike, status.User.Username, "user should have username")
	assert.Equal(t, e.groups, status.User.Groups, "user should have groups")
	if e.extra == nil {
		assert.Empty(t, status.User.Extra, "user should not have extra")
	} else {
		actualExtra := make(backend.Extra)
		mapstructure.Decode(status.User.Extra, &actualExtra)
		assert.Equal(t, e.extra, actualExtra, "user should have extra")
	}
}

func getCluster(t *testing.T) *vault.TestCluster {
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"kubernetes": backend.Factory,
		},
		CredentialBackends: map[string]logical.Factory{
			"userpass": userpass.Factory,
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
	err = client.Sys().EnableAuthWithOptions("userpass-mnt", &api.EnableAuthOptions{
		Type: "userpass",
	})
	require.NoError(t, err)
	return cluster
}

func TestIntegration_Vault(t *testing.T) {
	t.Parallel()
	cluster := getCluster(t)
	defer func() {
		cluster.Cleanup()
	}()
	r := vaultReviewer{
		url: cluster.Cores[0].Client.Address() + "/v1/kubernetes/tokenreviews",
	}
	runBackendTests(t, cluster, r)
}

func getKubeTargetPort() string {
	port := os.Getenv(kubeTargetPortEnv)
	if port == "" {
		return "8200"
	}
	return port
}

func TestIntegration_Kubernetes(t *testing.T) {
	t.Parallel()
	cluster := getCluster(t)
	defer cluster.Cleanup()
	// To provide an HTTP target on a pre-arranged port (much simpler for
	// configuring the test Kubernetes cluster), run an HTTP reverse proxy
	// to the test Vault cluster.
	clusterUrl, err := url.Parse(cluster.Cores[0].Client.Address())
	require.NoError(t, err, "parsing cluster url")
	proxy := httputil.NewSingleHostReverseProxy(clusterUrl)
	proxy.Transport = insecureTransport
	port := os.Getenv(kubeTargetPortEnv)
	if port == "" {
		port = "8200"
	}
	lis, err := net.Listen("tcp", "0.0.0.0:"+getKubeTargetPort())
	require.NoError(t, err, "listening on Kubernetes target port")
	srv := &http.Server{Handler: proxy}
	go func() {
		assert.Equal(t, http.ErrServerClosed, srv.Serve(lis), "proxy shutdown error")
	}()
	defer func() {
		assert.NoError(t, srv.Shutdown(context.Background()), "shutting down proxy")
	}()
	runBackendTests(t, cluster, kubeReviewer{})

	t.Run("ClientPlugin", func(t *testing.T) {
		testKubernetesClientPlugin(t, cluster.Cores[0].Client)
	})
}

func runBackendTests(t *testing.T, cluster *vault.TestCluster, r reviewer) {
	type tc func(*testing.T, *api.Client, reviewer)
	cases := map[string]tc{
		"UnknownTokenDenied":       testUnknownTokenDenied,
		"TokenWithGroupsAndExtras": testTokenWithGroupsAndExtras,
		"TokenAllowedUntilExpired": testTokenAllowedUntilExpired,
		"TokenAllowedUntilRevoked": testTokenAllowedUntilRevoked,
		"TokenAllowedAfterRenewed": testTokenAllowedAfterRenewed,
		"TokenWithIdentity":        testTokenWithIdentity,
	}
	// Group the subtests so they can be run in parallel.
	t.Run("TokenReviews", func(t *testing.T) {
		for name, c := range cases {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				c(t, cluster.Cores[0].Client, r)
			})
		}
	})
}

func testUnknownTokenDenied(t *testing.T, c *api.Client, r reviewer) {
	r.assertDenied(t, "notavalidtoken")
}

func testTokenWithGroupsAndExtras(t *testing.T, c *api.Client, r reviewer) {
	_, err := c.Logical().Write("kubernetes/roles/groups-and-extras", map[string]interface{}{
		"groups": []string{
			"group1",
			"group2",
		},
		"extra": backend.Extra{
			"a": []string{"a1", "a2"},
			"b": []string{"a1"},
			"c": []string{},
		},
	})
	require.NoError(t, err)
	tokenResp, err := c.Logical().Read("kubernetes/token/groups-and-extras")
	require.NoError(t, err)
	token := tokenResp.Data["token"].(string)
	r.assertAllowed(t, token, expectedAllow{
		usernameLike: "v_root_groups-and-extras_.*",
		groups:       []string{"group1", "group2"},
		extra: backend.Extra{
			"a": []string{"a1", "a2"},
			"b": []string{"a1"},
			"c": []string{},
		},
	})
}

func testTokenAllowedUntilExpired(t *testing.T, c *api.Client, r reviewer) {
	_, err := c.Logical().Write("kubernetes/roles/expire-fast", map[string]interface{}{
		"groups":      []string{"group1"},
		"default_ttl": "3s",
	})
	require.NoError(t, err)

	expireTime := time.Now().Add(3 * time.Second)
	tokenResp, err := c.Logical().Read("kubernetes/token/expire-fast")
	require.NoError(t, err)
	assert.Equal(t, 3, tokenResp.LeaseDuration)

	r.awaitDenied(t, tokenResp.Data["token"].(string), expireTime)
}

func testTokenAllowedUntilRevoked(t *testing.T, c *api.Client, r reviewer) {
	_, err := c.Logical().Write("kubernetes/roles/will-revoke", map[string]interface{}{
		"groups":      []string{"group1"},
		"default_ttl": "1h",
	})
	require.NoError(t, err)
	tokenResp, err := c.Logical().Read("kubernetes/token/will-revoke")
	require.NoError(t, err)
	assert.Equal(t, 1*60*60, tokenResp.LeaseDuration)
	token := tokenResp.Data["token"].(string)

	r.assertAllowed(t, token, expectedAllow{
		usernameLike: "v_root_will-revoke_.*",
		groups:       []string{"group1"},
	})

	err = c.Sys().Revoke(tokenResp.LeaseID)
	require.NoError(t, err)

	r.awaitDenied(t, tokenResp.Data["token"].(string), time.Now())
}

func testTokenAllowedAfterRenewed(t *testing.T, c *api.Client, r reviewer) {
	_, err := c.Logical().Write("kubernetes/roles/will-renew", map[string]interface{}{
		"groups":      []string{"group1"},
		"default_ttl": "3s",
	})
	require.NoError(t, err)
	tokenResp, err := c.Logical().Read("kubernetes/token/will-renew")
	require.NoError(t, err)
	assert.Equal(t, 3, tokenResp.LeaseDuration)
	assert.True(t, tokenResp.Renewable)
	token := tokenResp.Data["token"].(string)

	renewResp, err := c.Sys().Renew(tokenResp.LeaseID, 10)
	require.NoError(t, err)
	assert.Equal(t, 10, renewResp.LeaseDuration)
	time.Sleep(5 * time.Second)

	r.assertAllowed(t, token, expectedAllow{
		usernameLike: "v_root_will-renew_.*",
		groups:       []string{"group1"},
	})
}

func testTokenWithIdentity(t *testing.T, c *api.Client, r reviewer) {
	// Set up a userpass-auth user who can read from the Kubernetes token endpoint.
	_, err := c.Logical().Write("auth/userpass-mnt/users/testuser", map[string]interface{}{
		"password": "testpass",
		"policies": "eng-policy",
	})
	require.NoError(t, err)
	err = c.Sys().PutPolicy("eng-policy", `
path "kubernetes/token/eng" {
  capabilities = ["read"]
}
`)
	require.NoError(t, err)
	_, err = c.Logical().Write("kubernetes/roles/eng", map[string]interface{}{
		"groups":      []string{"eng"},
		"default_ttl": "3s",
	})
	require.NoError(t, err)

	// Log in as the test user.
	uc, err := c.Clone()
	require.NoError(t, err)
	uc.ClearToken()
	resp, err := uc.Logical().Write("auth/userpass-mnt/login/testuser", map[string]interface{}{
		"password": "testpass",
	})
	require.NoError(t, err)
	uc.SetToken(resp.Auth.ClientToken)

	// Get a Kubernetes token as the user.
	tokenResp, err := uc.Logical().Read("kubernetes/token/eng")
	require.NoError(t, err)
	token := tokenResp.Data["token"].(string)
	r.assertAllowed(t, token, expectedAllow{
		usernameLike: "testuser_auth_userpass_.*",
		groups:       []string{"eng"},
	})
}

// testKubernetesClientPlugin is an end-to-end test of the Kubernetes client plugin.
func testKubernetesClientPlugin(t *testing.T, vaultClient *api.Client) {
	cacheDir, err := ioutil.TempDir("", "")
	defer os.RemoveAll(cacheDir)
	cacheFile := path.Join(cacheDir, "token-cache")

	_, err = vaultClient.Logical().Write("kubernetes/roles/cluster-admin", map[string]interface{}{
		"groups": []string{
			"cluster-admin",
		},
	})
	require.NoError(t, err)

	kubeConfig, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	require.NoError(t, err)
	if kubeContext := os.Getenv(kubeContextEnv); kubeContext != "" {
		kubeConfig.CurrentContext = kubeContext
	}

	pluginCmd, err := filepath.Abs("../../bin/kubernetes-credential-provider-vault")
	require.NoError(t, err)

	// Create a child token so we can revoke it to test revocation.
	s, err := vaultClient.Logical().Write("auth/token/create", map[string]interface{}{})
	require.NoError(t, err)
	childToken := s.Auth.ClientToken
	require.NotEmpty(t, childToken)

	configOverrides := &clientcmd.ConfigOverrides{
		AuthInfo: kubeApi.AuthInfo{
			Exec: &kubeApi.ExecConfig{
				APIVersion: "client.authentication.k8s.io/v1alpha1",
				Command:    pluginCmd,
				Env: []kubeApi.ExecEnvVar{
					{"KUBE_VAULT_PATH", "kubernetes"},
					{"KUBE_VAULT_ROLE", "cluster-admin"},
					{"KUBE_VAULT_CACHE", cacheFile},
					{"VAULT_TOKEN", childToken},
					{"VAULT_ADDR", "http://localhost:" + getKubeTargetPort()},
				},
			},
		},
	}

	restClientConfig, err := clientcmd.NewDefaultClientConfig(*kubeConfig, configOverrides).ClientConfig()
	require.NoError(t, err)
	// Make sure TLS client keys don't sneak in to authentication flow.
	restClientConfig.TLSClientConfig.CertFile = ""
	restClientConfig.TLSClientConfig.KeyFile = ""
	kubeClient, err := kubernetes.NewForConfig(restClientConfig)
	require.NoError(t, err)

	// The client plugin should fetch and use Kubernetes credentials from Vault.
	namespaces, err := kubeClient.CoreV1().Namespaces().List(metav1.ListOptions{})
	assert.NoError(t, err, "kubernetes request should be allowed")
	assert.NotEmpty(t, namespaces.Items)
	assertCacheSize(t, cacheFile, 1)

	// To check that auth was actually happening via Vault creds, revoke the creds and
	// wait for a denial.
	_, err = vaultClient.Logical().Write("/auth/token/revoke", map[string]interface{}{
		"token": childToken,
	})
	require.NoError(t, err)
	isDenied := func() bool {
		_, err := kubeClient.CoreV1().Namespaces().List(metav1.ListOptions{})
		if err != nil {
			assert.True(t, errors.IsUnauthorized(err), "Kubernetes error should be UNAUTHORIZED")
			return true
		}
		return false
	}
	awaitDenied(t, isDenied, time.Now(), 20*time.Second)
	// After the revocation, the entry should be cleared from the cache.
	assertCacheSize(t, cacheFile, 0)
}

func assertCacheSize(t *testing.T, file string, expectedSize int) {
	if r, err := os.Open(file); assert.NoError(t, err) {
		defer r.Close()
		var entries []interface{}
		assert.NoError(t, json.NewDecoder(r).Decode(&entries))
		assert.Equal(t, expectedSize, len(entries), "cache file should have entries")
	}
}
