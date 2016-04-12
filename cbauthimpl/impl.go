// @author Couchbase <info@couchbase.com>
// @copyright 2015 Couchbase, Inc.
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

// Package cbauthimpl contains internal implementation details of
// cbauth. It's APIs are subject to change without notice.
package cbauthimpl

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Node struct is used as part of Cache messages to describe creds and
// ports of some cluster node.
type Node struct {
	Host     string
	User     string
	Password string
	Ports    []int
	Local    bool
}

func matchHost(n Node, host string) bool {
	if n.Host == "127.0.0.1" {
		return true
	}
	if host == "127.0.0.1" && n.Local {
		return true
	}
	return host == n.Host
}

func getMemcachedCreds(n Node, host string, port int) (user, password string) {
	if !matchHost(n, host) {
		return "", ""
	}
	for _, p := range n.Ports {
		if p == port {
			return n.User, n.Password
		}
	}
	return "", ""
}

// User struct is used as part of Cache messages to describe creds of
// some user (admin or ro-admin).
type User struct {
	User string
	Salt []byte
	Mac  []byte
}

// Bucket struct is used as part of Cache messages to describe bucket auth
type Bucket struct {
	Name     string
	Password string
}

func verifyCreds(u User, user, password string) bool {
	if u.User == "" || u.User != user {
		return false
	}

	mac := hmac.New(sha1.New, u.Salt)
	mac.Write([]byte(password))
	return hmac.Equal(u.Mac, mac.Sum(nil))
}

type credsDB struct {
	nodes              []Node
	buckets            map[string]string
	admin              User
	roadmin            User
	hasNoPwdBucket     bool
	authCheckURL       string
	permissionCheckURL string
	specialUser        string
	specialPassword    string
	permissionsVersion int
	ldapEnabled        bool
}

// Cache is a structure into which the revrpc json is unmarshalled
type Cache struct {
	Nodes              []Node
	Buckets            []Bucket
	Admin              User
	ROAdmin            User   `json:"roAdmin"`
	AuthCheckURL       string `json:"authCheckUrl"`
	PermissionCheckURL string `json:"permissionCheckUrl"`
	SpecialUser        string `json:"specialUser"`
	PermissionsVersion int
	LDAPEnabled        bool
}

// CredsImpl implements cbauth.Creds interface.
type CredsImpl struct {
	name     string
	source   string
	password string
	db       *credsDB
	s        *Svc
}

// Name method returns user name (e.g. for auditing)
func (c *CredsImpl) Name() string {
	return c.name
}

// Source method returns user source (for auditing)
func (c *CredsImpl) Source() string {
	switch c.source {
	case "admin", "ro_admin":
		return "ns_server"
	}
	return c.source
}

// IsAllowed method returns true if the permission is granted
// for these credentials
func (c *CredsImpl) IsAllowed(permission string) (bool, error) {
	return checkPermission(c.s, c.name, c.source, permission)
}

func verifySpecialCreds(db *credsDB, user, password string) bool {
	return len(user) > 0 && user[0] == '@' && password == db.specialPassword
}

func checkBucketPassword(db *credsDB, bucket, givenPassword string) bool {
	// TODO: one day we'll care enough to do something like
	// subtle.ConstantTimeCompare, but note that it's going to be
	// trickier than just using that function alone. For that
	// reason, I'm keeping away from trouble for now.
	pwd, exists := db.buckets[bucket]
	return exists && pwd == givenPassword
}

// Svc is a struct that holds state of cbauth service.
type Svc struct {
	l         sync.Mutex
	db        *credsDB
	staleErr  error
	freshChan chan struct{}
	upCache   *userPermissionCache
	cacheOnce sync.Once
}

func cacheToCredsDB(c *Cache) (db *credsDB) {
	db = &credsDB{
		nodes:              c.Nodes,
		buckets:            make(map[string]string),
		admin:              c.Admin,
		roadmin:            c.ROAdmin,
		hasNoPwdBucket:     false,
		authCheckURL:       c.AuthCheckURL,
		permissionCheckURL: c.PermissionCheckURL,
		ldapEnabled:        c.LDAPEnabled,
		specialUser:        c.SpecialUser,
		permissionsVersion: c.PermissionsVersion,
	}
	for _, bucket := range c.Buckets {
		if bucket.Password == "" {
			db.hasNoPwdBucket = true
		}
		db.buckets[bucket.Name] = bucket.Password
	}
	for _, node := range db.nodes {
		if node.Local {
			db.specialPassword = node.Password
			break
		}
	}
	return
}

func updateDBLocked(s *Svc, db *credsDB) {
	s.db = db
	if s.freshChan != nil {
		close(s.freshChan)
		s.freshChan = nil
	}
}

// UpdateDB is a revrpc method that is used by ns_server update cbauth
// state.
func (s *Svc) UpdateDB(c *Cache, outparam *bool) error {
	if outparam != nil {
		*outparam = true
	}
	// BUG(alk): consider some kind of CAS later
	db := cacheToCredsDB(c)
	s.l.Lock()
	updateDBLocked(s, db)
	s.l.Unlock()
	return nil
}

// ResetSvc marks service's db as stale.
func ResetSvc(s *Svc, staleErr error) {
	if staleErr == nil {
		panic("staleErr must be non-nil")
	}
	s.l.Lock()
	s.staleErr = staleErr
	updateDBLocked(s, nil)
	s.l.Unlock()
}

func staleError(s *Svc) error {
	if s.staleErr == nil {
		panic("impossible Svc state where staleErr is nil!")
	}
	return s.staleErr
}

// NewSVC constructs Svc instance. Period is initial period of time
// where attempts to access stale DB won't cause DBStaleError responses,
// but service will instead wait for UpdateDB call.
func NewSVC(period time.Duration, staleErr error) *Svc {
	return NewSVCForTest(period, staleErr, func(period time.Duration, freshChan chan struct{}, body func()) {
		time.AfterFunc(period, body)
	})
}

// NewSVCForTest constructs Svc isntance.
func NewSVCForTest(period time.Duration, staleErr error, waitfn func(time.Duration, chan struct{}, func())) *Svc {
	if staleErr == nil {
		panic("staleErr must be non-nil")
	}
	s := &Svc{staleErr: staleErr}
	if period != time.Duration(0) {
		s.freshChan = make(chan struct{})
		waitfn(period, s.freshChan, func() {
			s.l.Lock()
			if s.freshChan != nil {
				close(s.freshChan)
				s.freshChan = nil
			}
			s.l.Unlock()
		})
	}
	return s
}

func fetchDB(s *Svc) *credsDB {
	s.l.Lock()
	db := s.db
	c := s.freshChan
	s.l.Unlock()

	if db != nil || c == nil {
		return db
	}

	// if db is stale try to wait a bit
	<-c
	// double receive doesn't change anything from correctness
	// standpoint (we close channel), but helps a lot for tests
	<-c
	s.l.Lock()
	db = s.db
	s.l.Unlock()

	return db
}

const tokenHeader = "ns-server-ui"

// IsAuthTokenPresent returns true iff ns_server's ui token header
// ("ns-server-ui") is set to "yes". UI is using that header to
// indicate that request is using so called token auth.
func IsAuthTokenPresent(req *http.Request) bool {
	return req.Header.Get(tokenHeader) == "yes"
}

func copyHeader(name string, from, to http.Header) {
	if val := from.Get(name); val != "" {
		to.Set(name, val)
	}
}

// IsLDAPEnabled returns true if ldap authentication is enabled
// on ns_server
func IsLDAPEnabled(s *Svc) (bool, error) {
	db := fetchDB(s)
	if db == nil {
		return false, staleError(s)
	}
	return s.db.ldapEnabled, nil
}

// VerifyOnServer verifies auth of given request by passing it to
// ns_server.
func VerifyOnServer(s *Svc, reqHeaders http.Header) (*CredsImpl, error) {
	db := fetchDB(s)
	if db == nil {
		return nil, staleError(s)
	}

	if s.db.authCheckURL == "" {
		return nil, nil
	}

	req, err := http.NewRequest("POST", db.authCheckURL, nil)
	if err != nil {
		panic(err)
	}

	copyHeader(tokenHeader, reqHeaders, req.Header)
	copyHeader("ns-server-auth-token", reqHeaders, req.Header)
	copyHeader("Cookie", reqHeaders, req.Header)
	copyHeader("Authorization", reqHeaders, req.Header)

	hresp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer hresp.Body.Close()
	if hresp.StatusCode == 401 {
		return nil, nil
	}

	if hresp.StatusCode != 200 {
		err = fmt.Errorf("Expecting 200 or 401 from ns_server auth endpoint. Got: %s", hresp.Status)
		return nil, err
	}

	body, err := ioutil.ReadAll(hresp.Body)
	if err != nil {
		return nil, err
	}

	resp := struct {
		User, Source string
	}{}
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return nil, err
	}

	rv := CredsImpl{name: resp.User, source: resp.Source, db: db, s: s}
	return &rv, nil
}

func checkPermission(s *Svc, user, source, permission string) (bool, error) {
	db := fetchDB(s)
	if db == nil {
		return false, staleError(s)
	}

	s.cacheOnce.Do(func() { s.upCache = newPermissionCache(db.permissionsVersion) })

	s.upCache.maybeRefreshCache(db.permissionsVersion)

	allowed, found := s.upCache.lookup(user, source, permission)
	if found {
		return allowed, nil
	}

	allowed, err := checkPermissionOnServer(db, user, source, permission)
	if err != nil {
		return false, err
	}
	s.upCache.set(user, source, permission, allowed, db.permissionsVersion)
	return allowed, nil
}

func checkPermissionOnServer(db *credsDB, user, source, permission string) (bool, error) {
	req, err := http.NewRequest("GET", db.permissionCheckURL, nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(db.specialUser, db.specialPassword)

	v := url.Values{}
	v.Set("user", user)
	v.Set("src", source)
	v.Set("permission", permission)
	req.URL.RawQuery = v.Encode()

	hresp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer hresp.Body.Close()

	switch hresp.StatusCode {
	case 200:
		return true, nil
	case 401:
		return false, nil
	}
	return false, fmt.Errorf("Unexpected return code %v", hresp.StatusCode)
}

// VerifyPassword verifies given user/password creds against cbauth
// password database. Returns nil, nil if given creds are not
// recognised at all.
func VerifyPassword(s *Svc, user, password string) (*CredsImpl, error) {
	db := fetchDB(s)
	if db == nil {
		return nil, staleError(s)
	}
	rv := &CredsImpl{name: user, password: password, db: db, s: s}

	switch {
	case verifySpecialCreds(db, user, password):
		rv.source = "admin"
	case verifyCreds(db.admin, user, password):
		rv.source = "admin"
	case verifyCreds(db.roadmin, user, password):
		rv.source = "ro_admin"
	case user == "":
		if !(password == "" && db.hasNoPwdBucket) {
			// we only allow anonymous access if password
			// is also empty and there is at least one
			// no-password bucket
			return nil, nil
		}
		rv.source = "anonymous"
	default:
		if !checkBucketPassword(db, user, password) {
			// right now we only grant access if username
			// matches specific bucket and bucket password
			// is given
			return nil, nil
		}
		rv.source = "bucket"
	}

	return rv, nil
}

// GetCreds returns service password for given host and port
// together with memcached admin name and http special user.
// Or "", "", "", nil if host/port represents unknown service.
func GetCreds(s *Svc, host string, port int) (memcachedUser, user, pwd string, err error) {
	db := fetchDB(s)
	if db == nil {
		return "", "", "", staleError(s)
	}
	for _, n := range db.nodes {
		memcachedUser, pwd = getMemcachedCreds(n, host, port)
		if memcachedUser != "" {
			user = db.specialUser
			return
		}
	}
	return
}

type userPermission struct {
	user       string
	src        string
	permission string
}

type userPermissionCache struct {
	sync.RWMutex
	version int
	m       map[userPermission]bool
}

func (c *userPermissionCache) clearNoLock() {
	c.m = make(map[userPermission]bool)
}

func (c *userPermissionCache) maybeRefreshCache(version int) {
	c.Lock()
	if c.version != version {
		c.clearNoLock()
		c.version = version
	}
	c.Unlock()
}

func newPermissionCache(version int) (c *userPermissionCache) {
	c = new(userPermissionCache)
	c.clearNoLock()
	c.version = version
	return
}

func (c *userPermissionCache) lookup(user, src, permission string) (allowed, found bool) {
	c.RLock()
	allowed, found = c.m[userPermission{user, src, permission}]
	c.RUnlock()
	return
}

func (c *userPermissionCache) set(user, src, permission string, allowed bool, version int) {
	c.Lock()
	if c.version == version {
		c.m[userPermission{user, src, permission}] = allowed
	}
	c.Unlock()
}
