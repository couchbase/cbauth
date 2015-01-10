// @author Couchbase <info@couchbase.com>
// @copyright 2014 Couchbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cache

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"github.com/couchbase/cbauth/revrpc"
	"net/http"
	"net/rpc"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TODO: infinite restart babysitting policy

// TODO: do several retries in case of stale cache

// AuthCache is a structure that implements cache that stores auth info
// received from ns_server via revrpc
type AuthCache struct {
	lock    sync.RWMutex
	stale   bool
	nodes   []node
	buckets map[string]string
	admin   user
	roadmin user
}

// AuthCacheSvc is revrpc service that ns_server uses to pass auth info
// updates to AuthCache
type AuthCacheSvc struct {
	cache *AuthCache
}

// UpdateCache is a method exported to be called by revrpc
func (svc *AuthCacheSvc) UpdateCache(req *Cache, ok *bool) (err error) {
	return svc.cache.UpdateCache(req, ok)
}

func (svc *AuthCacheSvc) getSetupRPCFun() func(*rpc.Server) error {
	return func(rs *rpc.Server) error {
		svc.cache.setStale()
		rs.Register(svc)
		return nil
	}
}

// UpdateCache is a method to be called by tests to trigger cache update
func (c *AuthCache) UpdateCache(req *Cache, ok *bool) (err error) {
	*ok = false
	buckets := make(map[string]string)
	for _, b := range req.Buckets {
		buckets[b.Name] = b.Password
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	c.nodes = req.Nodes
	c.admin = req.Admin
	c.roadmin = req.ROAdmin
	c.buckets = buckets
	c.stale = false

	*ok = true
	return
}

// StartAuthCache creates AuthCache and possibly starts revrpc service
func StartAuthCache(runRevRPC bool) (cache *AuthCache) {
	cache = &AuthCache{
		lock:  sync.RWMutex{},
		stale: true,
	}
	svc := &AuthCacheSvc{
		cache: cache,
	}
	if runRevRPC {
		go func() {
			for {
				revrpc.BabysitService(svc.getSetupRPCFun(), nil, nil)
				// FIXME: this is cheap way to limit
				// rate of restarts for now
				time.Sleep(100 * time.Millisecond)
			}
		}()
	}
	return
}

func (c *AuthCache) setStale() {
	c.lock.Lock()
	c.stale = true
	c.lock.Unlock()
}

// ErrAuthNotSupportedByCache: Auth on request is not supported by cache
var ErrAuthNotSupportedByCache = errors.New("Auth on request is not supported by cache")

// Err401: Unauthorized
var Err401 = errors.New("Unauthorized")

// ErrStale: Auth cache is stale. Please retry later
var ErrStale = errors.New("Auth cache is stale. Please retry later")

func extractCreds(req *http.Request) (user string, pwd string, err error) {
	if req.Header.Get("ns_server-ui") == "yes" {
		err = ErrAuthNotSupportedByCache
		return
	}

	auth := req.Header.Get("Authorization")
	if auth == "" {
		return "", "", nil
	}

	basicPrefix := "Basic "
	if !strings.HasPrefix(auth, basicPrefix) {
		err = errors.New("Non-basic auth is not supported")
		return
	}
	decodedAuth, err := base64.StdEncoding.DecodeString(auth[len(basicPrefix):])
	if err != nil {
		return
	}
	idx := bytes.IndexByte(decodedAuth, ':')
	if idx < 0 {
		err = errors.New("Malformed basic auth header")
		return
	}
	user = string(decodedAuth[0:idx])
	pwd = string(decodedAuth[(idx + 1):])
	return
}

func waitNonStale(c *AuthCache) {
	for i := 3; i > 0; i-- {
		var stale bool
		c.lock.RLock()
		stale = c.stale
		c.lock.RUnlock()
		if !stale {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	return
}

// VerifyCreds is a method that is called by cbauth to verify credentials against cache
func (c *AuthCache) VerifyCreds(req *http.Request) (user, role string, buckets map[string]bool, err error) {
	user, pwd, err := extractCreds(req)
	if err != nil {
		return
	}

	waitNonStale(c)

	c.lock.RLock()
	defer c.lock.RUnlock()

	if c.stale {
		err = ErrStale
		return
	}

	if c.admin.verifyCreds(user, pwd) {
		role = "admin"
		return
	}

	if c.roadmin.verifyCreds(user, pwd) {
		role = "ro_admin"
		return
	}

	if user == "" {
		role = "anonymous"
		user = "anonymous"
		buckets = make(map[string]bool)
		for n, p := range c.buckets {
			if p == "" {
				buckets[n] = true
			}
		}
		if len(buckets) == 0 {
			err = Err401
		}
		return
	}

	if c.buckets[user] == pwd {
		role = "bucket"
		return
	}

	err = Err401
	return
}

// GetHTTPServiceAuth is a method called by cbauth to obtain auth for http access to ns_server
func (c *AuthCache) GetHTTPServiceAuth(hostport string) (user, pwd string, err error) {
	user, pwd, err = c.GetMemcachedServiceAuth(hostport)
	if err != nil {
		return
	}
	user = "@"
	return
}

// GetMemcachedServiceAuth is a method called by cbauth to obtain auth for access to memcached
func (c *AuthCache) GetMemcachedServiceAuth(hostport string) (user, pwd string, err error) {
	tokens := strings.Split(hostport, ":")
	if len(tokens) != 2 {
		err = errors.New("Invalid hostport")
		return
	}
	host := tokens[0]
	port, err := strconv.ParseInt(tokens[1], 10, 0)
	if err != nil {
		return
	}

	waitNonStale(c)

	c.lock.RLock()
	defer c.lock.RUnlock()

	if c.stale {
		err = ErrStale
		return
	}

	for _, n := range c.nodes {
		user, pwd = n.getMemcachedCreds(host, int(port))
		if user != "" {
			return
		}
	}
	err = errors.New("Credentials for given hostport are not found")
	return
}

type node struct {
	Host     string
	User     string `json:"admin_user"`
	Password string `json:"admin_pass"`
	Ports    []int
	Local    bool
}

func (n *node) matchHost(host string) bool {
	// single node in the cluster. must be it regardless of passed host
	if n.Host == "127.0.0.1" {
		return true
	}
	if host == "127.0.0.1" && n.Local {
		return true
	}
	return host == n.Host
}

func (n *node) getMemcachedCreds(host string, port int) (user, password string) {
	if !n.matchHost(host) {
		return "", ""
	}
	for _, p := range n.Ports {
		if p == port {
			return n.User, n.Password
		}
	}
	return "", ""
}

type user struct {
	User string
	Salt []byte
	Mac  []byte
}

func (u *user) verifyCreds(user, password string) bool {
	if u.User == "" || u.User != user {
		return false
	}

	mac := hmac.New(sha1.New, u.Salt)
	mac.Write([]byte(password))
	return hmac.Equal(u.Mac, mac.Sum(nil))
}

type bucket struct {
	Name     string
	Password string
}

// Cache is a structure into which the revrpc json is unmarshalled
type Cache struct {
	Nodes   []node
	Buckets []bucket
	Admin   user
	ROAdmin user `json:"ro_admin"`
}

// NewTestCache is a function that is called by tests to create Cache structure
func NewTestCache() *Cache {
	return &Cache{
		Nodes:   make([]node, 0),
		Buckets: make([]bucket, 0),
	}
}

// SetUser is used by tests to add admin or roadmin user to Cache
func (c *Cache) SetUser(userName, password, role string, salt []byte) {
	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte(password))
	if role == "admin" {
		c.Admin.User = userName
		c.Admin.Salt = salt
		c.Admin.Mac = mac.Sum(nil)
	} else {
		c.ROAdmin.User = userName
		c.ROAdmin.Salt = salt
		c.ROAdmin.Mac = mac.Sum(nil)
	}
}

// AddBucket is used by tests to add bucket to Cache
func (c *Cache) AddBucket(bucketName, password string) {
	c.Buckets = append(c.Buckets, bucket{
		Name:     bucketName,
		Password: password,
	})
}
