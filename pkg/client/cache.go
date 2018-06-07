package client

import (
	"encoding/json"
	"fmt"
	"io"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"path"
	"time"
)

var (
	defaultCacheFile = path.Join(clientcmd.RecommendedConfigDir, "vault-plugin-tokens")
)

// tokenCache is a simple JSON-file-backed cache of Kubernetes credentials.
type tokenCache struct {
	entries []*cacheEntry
	file    string
}

type cacheEntry struct {
	// The "key" fields.
	Addr string `json:"addr"`
	Path string `json:"path"`
	Role string `json:"role"`

	Token      string    `json:"token"`
	Expiration time.Time `json:"expiration"`
	Lease      string    `json:"lease"`
	Renewable  bool      `json:"renewable"`
}

func loadCache(file string) (*tokenCache, error) {
	if file == "" {
		file = defaultCacheFile
	}
	c := &tokenCache{file: file}
	r, err := os.Open(file)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, err
	}
	defer r.Close()

	err = json.NewDecoder(r).Decode(&c.entries)
	// Allow EOF errors so /dev/null is a valid cache file.
	if err != nil && err != io.EOF {
		return nil, err
	}
	return c, nil
}

func (_ tokenCache) keysEqual(a, b *cacheEntry) bool {
	return a.Addr == b.Addr && a.Path == b.Path && a.Role == b.Role
}

func (c *tokenCache) Get(addr, path, role string) *cacheEntry {
	key := &cacheEntry{Addr: addr, Path: path, Role: role}
	for _, e := range c.entries {
		if c.keysEqual(key, e) {
			return e
		}
	}
	return nil
}

func (c *tokenCache) Put(u *cacheEntry) {
	for i, e := range c.entries {
		if c.keysEqual(u, e) {
			c.entries[i] = u
			return
		}
	}
	c.entries = append(c.entries, u)
}

func (c *tokenCache) Delete(u *cacheEntry) {
	for i, e := range c.entries {
		if c.keysEqual(u, e) {
			c.entries = append(c.entries[:i], c.entries[i+1:]...)
			return
		}
	}
}

func (c *tokenCache) WriteOut() error {
	w, err := os.OpenFile(c.file, os.O_CREATE|os.O_TRUNC|os.O_RDWR, os.FileMode(0600))
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("parent does not exist for %s file %s", cacheEnv, c.file)
		}
		return err
	}
	defer w.Close()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(&c.entries)
}
