package kubernetes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// RestAPI implements API against a Kubernetes API server using plain
// REST calls with a bearer token. All requests are read-only GETs.
type RestAPI struct {
	baseURL string
	token   string
	client  *http.Client
}

// RestOptions configures RestAPI construction.
type RestOptions struct {
	Server string
	Token  string
	// CAData is a PEM bundle for the API server (optional).
	CAData []byte
	// InsecureSkipTLSVerify disables certificate verification.
	InsecureSkipTLSVerify bool
}

// NewRestAPI builds a REST client.
func NewRestAPI(opts RestOptions) (*RestAPI, error) {
	if opts.Server == "" {
		return nil, fmt.Errorf("kubernetes connector: API server URL is required")
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: opts.InsecureSkipTLSVerify} //nolint:gosec
	if len(opts.CAData) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(opts.CAData) {
			return nil, fmt.Errorf("kubernetes connector: invalid CA data")
		}
		tlsCfg.RootCAs = pool
	}
	return &RestAPI{
		baseURL: opts.Server,
		token:   opts.Token,
		client:  &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}},
	}, nil
}

// LoadRestAPI resolves API access from, in order:
//  1. explicit server/token options
//  2. a kubeconfig file (default ~/.kube/config)
//  3. in-cluster environment (KUBERNETES_SERVICE_HOST + service account)
func LoadRestAPI(ctx context.Context, opts RestOptions, kubeconfigPath string) (*RestAPI, error) {
	if opts.Server != "" {
		return NewRestAPI(opts)
	}
	if kubeconfigPath == "" {
		home, _ := os.UserHomeDir()
		kubeconfigPath = filepath.Join(home, ".kube", "config")
	}
	if data, err := os.ReadFile(kubeconfigPath); err == nil {
		cfg, err := parseKubeconfig(data)
		if err != nil {
			return nil, fmt.Errorf("kubernetes connector: kubeconfig: %w", err)
		}
		if cfg.Insecure {
			fmt.Fprintf(os.Stderr, "warning: kubeconfig sets insecure-skip-tls-verify; API server identity will not be verified\n")
		}
		ro := RestOptions{
			Server:                cfg.Server,
			Token:                 cfg.Token,
			CAData:                cfg.CAData,
			InsecureSkipTLSVerify: cfg.Insecure || opts.InsecureSkipTLSVerify,
		}
		if opts.Token != "" {
			ro.Token = opts.Token
		}
		if ro.Server != "" {
			return NewRestAPI(ro)
		}
	}
	// In-cluster: env-provided host + mounted service account token.
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host != "" && port != "" {
		token := opts.Token
		if token == "" {
			b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
			if err != nil {
				return nil, fmt.Errorf("kubernetes connector: in-cluster token: %w", err)
			}
			token = string(b)
		}
		var caData []byte
		if ca, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"); err == nil {
			caData = ca
		}
		return NewRestAPI(RestOptions{
			Server: "https://" + host + ":" + port,
			Token:  token,
			CAData: caData,
		})
	}
	return nil, fmt.Errorf("kubernetes connector: no API server access configured (pass --server/--token, a kubeconfig, or run in-cluster)")
}

// kubeconfig is the minimal subset of the kubeconfig format.
type kubeconfig struct {
	Server   string
	Token    string
	CAData   []byte
	Insecure bool
}

func parseKubeconfig(data []byte) (*kubeconfig, error) {
	var raw struct {
		CurrentContext string `yaml:"current-context"`
		Contexts       []struct {
			Name    string `yaml:"name"`
			Context struct {
				Cluster string `yaml:"cluster"`
				User    string `yaml:"user"`
			} `yaml:"context"`
		} `yaml:"contexts"`
		Clusters []struct {
			Name    string `yaml:"name"`
			Cluster struct {
				Server                   string `yaml:"server"`
				CertificateAuthorityData string `yaml:"certificate-authority-data"`
				InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
			} `yaml:"cluster"`
		} `yaml:"clusters"`
		Users []struct {
			Name string `yaml:"name"`
			User struct {
				Token     string `yaml:"token"`
				TokenFile string `yaml:"tokenFile"`
			} `yaml:"user"`
		} `yaml:"users"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	ctxName := raw.CurrentContext
	var clusterName, userName string
	for _, c := range raw.Contexts {
		if c.Name == ctxName {
			clusterName = c.Context.Cluster
			userName = c.Context.User
			break
		}
	}

	cfg := &kubeconfig{}
	for _, cl := range raw.Clusters {
		if cl.Name == clusterName {
			cfg.Server = cl.Cluster.Server
			cfg.Insecure = cl.Cluster.InsecureSkipTLSVerify
			if cl.Cluster.CertificateAuthorityData != "" {
				ca, err := base64.StdEncoding.DecodeString(cl.Cluster.CertificateAuthorityData)
				if err != nil {
					return nil, fmt.Errorf("certificate-authority-data: %w", err)
				}
				cfg.CAData = ca
			}
			break
		}
	}
	for _, u := range raw.Users {
		if u.Name == userName {
			cfg.Token = u.User.Token
			if cfg.Token == "" && u.User.TokenFile != "" {
				if b, err := os.ReadFile(u.User.TokenFile); err == nil {
					cfg.Token = string(b)
				}
			}
			break
		}
	}
	return cfg, nil
}

// listResult is the shared list envelope.
type listResult struct {
	Items []json.RawMessage `json:"items"`
}

func (a *RestAPI) get(ctx context.Context, path string, out any) error {
	url := a.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GET %s: http %d: %s", path, resp.StatusCode, string(body))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

func (a *RestAPI) listCore(ctx context.Context, resource string, out any) error {
	return a.get(ctx, "/api/v1/"+resource, out)
}

func (a *RestAPI) listRBAC(ctx context.Context, resource string, out any) error {
	return a.get(ctx, "/apis/rbac.authorization.k8s.io/v1/"+resource, out)
}

type objectMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// ListPods implements API.
func (a *RestAPI) ListPods(ctx context.Context) ([]Pod, error) {
	var list struct {
		Items []struct {
			Metadata objectMeta `json:"metadata"`
			Spec     struct {
				ServiceAccountName string `json:"serviceAccountName"`
			} `json:"spec"`
		} `json:"items"`
	}
	if err := a.listCore(ctx, "pods", &list); err != nil {
		return nil, err
	}
	var out []Pod
	for _, p := range list.Items {
		out = append(out, Pod{
			Name:           p.Metadata.Name,
			Namespace:      p.Metadata.Namespace,
			ServiceAccount: p.Spec.ServiceAccountName,
		})
	}
	return out, nil
}

// ListServiceAccounts implements API.
func (a *RestAPI) ListServiceAccounts(ctx context.Context) ([]ServiceAccount, error) {
	var list struct {
		Items []struct {
			Metadata objectMeta `json:"metadata"`
		} `json:"items"`
	}
	if err := a.listCore(ctx, "serviceaccounts", &list); err != nil {
		return nil, err
	}
	var out []ServiceAccount
	for _, sa := range list.Items {
		out = append(out, ServiceAccount{Name: sa.Metadata.Name, Namespace: sa.Metadata.Namespace})
	}
	return out, nil
}

// ListSecrets implements API. Values are never requested.
func (a *RestAPI) ListSecrets(ctx context.Context) ([]Secret, error) {
	var list struct {
		Items []struct {
			Metadata objectMeta `json:"metadata"`
			Type     string     `json:"type"`
		} `json:"items"`
	}
	if err := a.listCore(ctx, "secrets", &list); err != nil {
		return nil, err
	}
	var out []Secret
	for _, s := range list.Items {
		// Skip service-account token secrets: infrastructure noise.
		if s.Type == "kubernetes.io/service-account-token" {
			continue
		}
		out = append(out, Secret{Name: s.Metadata.Name, Namespace: s.Metadata.Namespace, Type: s.Type})
	}
	return out, nil
}

func (a *RestAPI) listRoles(ctx context.Context, resource string) ([]Role, error) {
	var list struct {
		Items []struct {
			Metadata objectMeta `json:"metadata"`
			Rules    []struct {
				Verbs     []string `json:"verbs"`
				Resources []string `json:"resources"`
			} `json:"rules"`
		} `json:"items"`
	}
	if err := a.listRBAC(ctx, resource, &list); err != nil {
		return nil, err
	}
	var out []Role
	for _, r := range list.Items {
		role := Role{Name: r.Metadata.Name, Namespace: r.Metadata.Namespace}
		for _, rule := range r.Rules {
			role.Rules = append(role.Rules, PolicyRule{Verbs: rule.Verbs, Resources: rule.Resources})
		}
		out = append(out, role)
	}
	return out, nil
}

// ListRoles implements API.
func (a *RestAPI) ListRoles(ctx context.Context) ([]Role, error) {
	return a.listRoles(ctx, "roles")
}

// ListClusterRoles implements API.
func (a *RestAPI) ListClusterRoles(ctx context.Context) ([]Role, error) {
	roles, err := a.listRoles(ctx, "clusterroles")
	if err != nil {
		return nil, err
	}
	for i := range roles {
		roles[i].Cluster = true
	}
	return roles, nil
}

func (a *RestAPI) listBindings(ctx context.Context, resource string) ([]RoleBinding, error) {
	var list struct {
		Items []struct {
			Metadata objectMeta `json:"metadata"`
			Subjects []struct {
				Kind      string `json:"kind"`
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"subjects"`
			RoleRef struct {
				Kind string `json:"kind"`
				Name string `json:"name"`
			} `json:"roleRef"`
		} `json:"items"`
	}
	if err := a.listRBAC(ctx, resource, &list); err != nil {
		return nil, err
	}
	var out []RoleBinding
	for _, rb := range list.Items {
		b := RoleBinding{Name: rb.Metadata.Name, Namespace: rb.Metadata.Namespace}
		for _, s := range rb.Subjects {
			b.Subjects = append(b.Subjects, Subject{Kind: s.Kind, Name: s.Name, Namespace: s.Namespace})
		}
		b.RoleRef.Kind = rb.RoleRef.Kind
		b.RoleRef.Name = rb.RoleRef.Name
		out = append(out, b)
	}
	return out, nil
}

// ListRoleBindings implements API.
func (a *RestAPI) ListRoleBindings(ctx context.Context) ([]RoleBinding, error) {
	return a.listBindings(ctx, "rolebindings")
}

// ListClusterRoleBindings implements API.
func (a *RestAPI) ListClusterRoleBindings(ctx context.Context) ([]RoleBinding, error) {
	return a.listBindings(ctx, "clusterrolebindings")
}
