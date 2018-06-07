package client

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"
)

func TestCache(t *testing.T) {
	dir, err := ioutil.TempDir("", "")
	defer os.RemoveAll(dir)
	require.NoError(t, err)
	file := path.Join(dir, "token-cache")
	c, err := loadCache(file)
	require.NoError(t, err)
	ret := c.Get("http://localhost:8200", "kubernetes", "role1")
	assert.Nil(t, ret, "no entry should be found initially")
	require.NoError(t, err)
	e := &cacheEntry{
		Addr:  "http://localhost:8200",
		Path:  "kubernetes",
		Role:  "role1",
		Token: "mytoken",
		Lease: "mylease",
		// Round(0) strips the monotonic clock reading (so we can compare).
		// Manually specified location ensures comparisons with == work.
		Expiration: time.Now().Add(5 * time.Minute).Round(0).In(time.UTC),
	}
	c.Put(e)
	ret = c.Get("http://localhost:8200", "kubernetes", "role1")
	assert.Equal(t, e, ret, "entry should be found after put")

	err = c.WriteOut()
	assert.NoError(t, err, "write out should succeed")

	c, err = loadCache(file)
	require.NoError(t, err)
	ret = c.Get("http://localhost:8200", "kubernetes", "role1")
	assert.Equal(t, e, ret, "entry should be found after put and reload")

	c.Delete(e)
	ret = c.Get("http://localhost:8200", "kubernetes", "role1")
	assert.Nil(t, ret, "no entry should be found after delete")

	err = c.WriteOut()
	assert.NoError(t, err, "write out should succeed")

	c, err = loadCache(file)
	require.NoError(t, err)
	ret = c.Get("http://localhost:8200", "kubernetes", "role1")
	assert.Nil(t, ret, "no entry should be found after delete and reload")
}

func TestCache_DevNull(t *testing.T) {
	c, err := loadCache(os.DevNull)
	require.NoError(t, err, "a /dev/null configured cache should load")
	assert.Empty(t, c.entries, "a /dev/null configured cache should be empty")
	e := &cacheEntry{
		Addr:  "http://localhost:8200",
		Path:  "kubernetes",
		Role:  "role1",
		Token: "mytoken",
		Lease: "mylease",
		// Round(0) strips the monotonic clock reading (so we can compare).
		Expiration: time.Now().Add(5 * time.Minute).Round(0),
	}
	c.Put(e)

	err = c.WriteOut()
	assert.NoError(t, err, "write out to /dev/null should succeed")

	c, err = loadCache(os.DevNull)
	require.NoError(t, err, "a /dev/null configured cache should load")
	assert.Empty(t, c.entries, "a /dev/null configured cache should be empty")
}
