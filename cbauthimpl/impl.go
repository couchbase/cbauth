// @author Couchbase <info@couchbase.com>
// @copyright 2015-2019 Couchbase, Inc.
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
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/couchbase/cbauth/utils"
)

// TLSRefreshCallback type describes callback for reinitializing TLSConfig when ssl certificate
// or client cert auth setting changes.
type TLSRefreshCallback func() error

const (
	CFG_CHANGE_CERTS_TLSCONFIG uint64 = 1 << iota
	CFG_CHANGE_CLUSTER_ENCRYPTION
	CFG_CHANGE_USER_LIMITS
	_MAX_CFG_CHANGE_FLAGS
)

// ConfigRefreshCallback type describes the callback called when any of the following
// are updated:
// 1. SSL certificates
// 2. TLS configuration
// 3. Cluster encryption configuration
//
// The clients are notified of the configuration changes by OR'ing
// the appropriate flags defined above and passing them as an argument to the
// callback function.
type ConfigRefreshCallback func(uint64) error

// TLSConfig contains tls settings to be used by cbauth clients
// When something in tls config changes user is notified via TLSRefreshCallback
type TLSConfig struct {
	MinVersion               uint16
	CipherSuites             []uint16
	CipherSuiteNames         []string
	CipherSuiteOpenSSLNames  []string
	PreferServerCipherSuites bool
	ClientAuthType           tls.ClientAuthType
	present                  bool
	PrivateKeyPassphrase     []byte
}

// LimitsConfig contains info about whether Limits needs to be enforced and what
// the limits version is.
type LimitsConfig struct {
	EnforceLimits     bool
	UserLimitsVersion string
}

// ClusterEncryptionConfig contains info about whether to use SSL ports for
// communication channels and whether to disable non-SSL ports.
type ClusterEncryptionConfig struct {
	EncryptData        bool
	DisableNonSSLPorts bool
}

type tlsConfigImport struct {
	MinTLSVersion        string
	Ciphers              []uint16
	CipherNames          []string
	CipherOpenSSLNames   []string
	CipherOrder          bool
	Present              bool
	PrivateKeyPassphrase []byte
}

// ErrNoAuth is an error that is returned when the user credentials
// are not recognized
var ErrNoAuth = errors.New("Authentication failure")

// ErrNoUuid is an error that is returned when the uuid for user is
// empty
var ErrNoUuid = errors.New("No UUID for user")

// ErrCallbackAlreadyRegistered is used to signal that certificate refresh callback is already registered
var ErrCallbackAlreadyRegistered = errors.New("Certificate refresh callback is already registered")

// ErrUserNotFound is used to signal when username can't be extracted from client certificate.
var ErrUserNotFound = errors.New("Username not found")

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
	NodeHostIP := net.ParseIP(n.Host)
	HostIP := net.ParseIP(host)

	if NodeHostIP.IsLoopback() {
		return true
	}
	if HostIP.IsLoopback() && n.Local {
		return true
	}

	// If both are IP addresses then use the standard API to check if they are equal.
	if NodeHostIP != nil && HostIP != nil {
		return HostIP.Equal(NodeHostIP)
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

type credsDB struct {
	nodeUUID                string
	nodes                   []Node
	authCheckURL            string
	permissionCheckURL      string
	limitsCheckURL          string
	uuidCheckURL            string
	specialUser             string
	specialPassword         string
	permissionsVersion      string
	userVersion             string
	authVersion             string
	certVersion             int
	extractUserFromCertURL  string
	clientCertAuthVersion   string
	limitsConfig            LimitsConfig
	clusterEncryptionConfig ClusterEncryptionConfig
	tlsConfig               TLSConfig
}

// Cache is a structure into which the revrpc json is unmarshalled
type Cache struct {
	Nodes                   []Node
	AuthCheckURL            string `json:"authCheckUrl"`
	PermissionCheckURL      string `json:"permissionCheckUrl"`
	LimitsCheckURL          string
	UuidCheckURL            string
	SpecialUser             string `json:"specialUser"`
	PermissionsVersion      string
	LimitsConfig            LimitsConfig
	UserVersion             string
	AuthVersion             string
	CertVersion             int
	ExtractUserFromCertURL  string                  `json:"extractUserFromCertURL"`
	ClientCertAuthState     string                  `json:"clientCertAuthState"`
	ClientCertAuthVersion   string                  `json:"clientCertAuthVersion"`
	ClusterEncryptionConfig ClusterEncryptionConfig `json:"clusterEncryptionConfig"`
	TLSConfig               tlsConfigImport         `json:"tlsConfig"`
}

// Cache is a structure into which the revrpc json is unmarshalled if
// used from external service
type CacheExt struct {
	AuthCheckEndpoint           string
	AuthVersion                 string
	PermissionCheckEndpoint     string
	PermissionsVersion          string
	ExtractUserFromCertEndpoint string
	ClientCertAuthVersion       string
	ClientCertAuthState         string
	NodeUUID                    string
}

// CredsImpl implements cbauth.Creds interface.
type CredsImpl struct {
	name     string
	domain   string
	uuid     string
	password string
	s        *Svc
}

// Name method returns user name (e.g. for auditing)
func (c *CredsImpl) Name() string {
	return c.name
}

// Domain method returns user domain (for auditing)
func (c *CredsImpl) Domain() string {
	switch c.domain {
	case "admin", "ro_admin":
		return "builtin"
	}
	return c.domain
}

// User method returns user and domain for non-auditing purpose.
func (c *CredsImpl) User() (name, domain string) {
	return c.name, c.domain
}

// User uuid used for generating user stats, need not be present.
// Only present for local users.
func (c *CredsImpl) Uuid() (string, error) {
	if c.uuid == "" {
		return c.uuid, ErrNoUuid
	}
	return c.uuid, nil
}

// IsAllowed method returns true if the permission is granted
// for these credentials
func (c *CredsImpl) IsAllowed(permission string) (bool, error) {
	return checkPermission(c.s, c.name, c.domain, permission)
}

func verifySpecialCreds(db *credsDB, user, password string) bool {
	return len(user) > 0 && user[0] == '@' && password == db.specialPassword
}

type semaphore chan int

func (s semaphore) signal() {
	<-s
}

func (s semaphore) wait() {
	s <- 1
}

type cfgChangeNotifier struct {
	l        sync.Mutex
	ch       chan uint64
	callback ConfigRefreshCallback
}

func newCfgChangeNotifier() *cfgChangeNotifier {
	return &cfgChangeNotifier{
		ch: make(chan uint64, 1),
	}
}

func (n *cfgChangeNotifier) notifyCfgChangeLocked(changes uint64) {
	select {
	case n.ch <- changes:
	default:
	}
}

func (n *cfgChangeNotifier) notifyCfgChange(changes uint64) {
	n.l.Lock()
	defer n.l.Unlock()
	n.notifyCfgChangeLocked(changes)
}

func (n *cfgChangeNotifier) registerCallback(callback ConfigRefreshCallback) error {
	n.l.Lock()
	defer n.l.Unlock()

	if n.callback != nil {
		return ErrCallbackAlreadyRegistered
	}

	n.callback = callback
	n.notifyCfgChangeLocked(_MAX_CFG_CHANGE_FLAGS - 1)
	return nil
}

func (n *cfgChangeNotifier) getCallback() ConfigRefreshCallback {
	n.l.Lock()
	defer n.l.Unlock()

	return n.callback
}

func (n *cfgChangeNotifier) maybeExecuteCallback(changes uint64) error {
	callback := n.getCallback()

	if callback != nil {
		return callback(changes)
	}
	return nil
}

func (n *cfgChangeNotifier) loop() {
	retry := (<-chan time.Time)(nil)
	var changes uint64 = 0

	for {
		select {
		case <-retry:
			retry = nil
		case changes = <-n.ch:
		}

		err := n.maybeExecuteCallback(changes)

		if err == nil {
			retry = nil
			changes = 0
			continue
		}

		if retry == nil {
			retry = time.After(5 * time.Second)
		}
	}
}

// NOTE: Type 'tlsNotifier' will be removed when all the clients start
//
//	using the new 'RegisterConfigRefreshCallback' API.
type tlsNotifier struct {
	l        sync.Mutex
	ch       chan struct{}
	callback TLSRefreshCallback
}

func newTLSNotifier() *tlsNotifier {
	return &tlsNotifier{
		ch: make(chan struct{}, 1),
	}
}

func (n *tlsNotifier) notifyTLSChangeLocked() {
	select {
	case n.ch <- struct{}{}:
	default:
	}
}

func (n *tlsNotifier) notifyTLSChange() {
	n.l.Lock()
	defer n.l.Unlock()
	n.notifyTLSChangeLocked()
}

func (n *tlsNotifier) registerCallback(callback TLSRefreshCallback) error {
	n.l.Lock()
	defer n.l.Unlock()

	if n.callback != nil {
		return ErrCallbackAlreadyRegistered
	}

	n.callback = callback
	n.notifyTLSChangeLocked()
	return nil
}

func (n *tlsNotifier) getCallback() TLSRefreshCallback {
	n.l.Lock()
	defer n.l.Unlock()

	return n.callback
}

func (n *tlsNotifier) maybeExecuteCallback() error {
	callback := n.getCallback()

	if callback != nil {
		return callback()
	}
	return nil
}

func (n *tlsNotifier) loop() {
	retry := (<-chan time.Time)(nil)

	for {
		select {
		case <-retry:
			retry = nil
		case <-n.ch:
		}

		err := n.maybeExecuteCallback()

		if err == nil {
			retry = nil
			continue
		}

		if retry == nil {
			retry = time.After(5 * time.Second)
		}
	}
}

// Svc is a struct that holds state of cbauth service.
type Svc struct {
	l                   sync.RWMutex
	db                  *credsDB
	staleErr            error
	freshChan           chan struct{}
	ulCache             *utils.Cache
	ulCacheOnce         sync.Once
	upCache             *utils.Cache
	upCacheOnce         sync.Once
	authCache           *utils.Cache
	authCacheOnce       sync.Once
	clientCertCache     *utils.Cache
	clientCertCacheOnce sync.Once
	uuidCacheOnce       sync.Once
	uuidCache           *utils.Cache
	httpClient          *http.Client
	semaphore           semaphore
	tlsNotifier         *tlsNotifier
	cfgChangeNotifier   *cfgChangeNotifier
	hostport            string
	user                string
	password            string
}

func cacheToCredsDB(c *Cache) (db *credsDB) {
	db = &credsDB{
		nodes:                   c.Nodes,
		authCheckURL:            c.AuthCheckURL,
		permissionCheckURL:      c.PermissionCheckURL,
		limitsCheckURL:          c.LimitsCheckURL,
		uuidCheckURL:            c.UuidCheckURL,
		specialUser:             c.SpecialUser,
		permissionsVersion:      c.PermissionsVersion,
		limitsConfig:            c.LimitsConfig,
		userVersion:             c.UserVersion,
		authVersion:             c.AuthVersion,
		certVersion:             c.CertVersion,
		extractUserFromCertURL:  c.ExtractUserFromCertURL,
		clientCertAuthVersion:   c.ClientCertAuthVersion,
		clusterEncryptionConfig: c.ClusterEncryptionConfig,
		tlsConfig:               importTLSConfig(&c.TLSConfig, c.ClientCertAuthState),
	}
	for _, node := range db.nodes {
		if node.Local {
			db.specialPassword = node.Password
			break
		}
	}
	return
}

func (s *Svc) cacheToCredsDBExt(c *CacheExt) (db *credsDB) {
	tlsConfig := TLSConfig{
		ClientAuthType: getAuthType(c.ClientCertAuthState),
	}
	db = &credsDB{
		authCheckURL:       s.buildUrl(c.AuthCheckEndpoint),
		permissionCheckURL: s.buildUrl(c.PermissionCheckEndpoint),
		permissionsVersion: c.PermissionsVersion,
		authVersion:        c.AuthVersion,
		extractUserFromCertURL: s.buildUrl(
			c.ExtractUserFromCertEndpoint),
		clientCertAuthVersion: c.ClientCertAuthVersion,
		specialUser:           s.user,
		specialPassword:       s.password,
		tlsConfig:             tlsConfig,
		nodeUUID:              c.NodeUUID,
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

// UpdateDBExt is a revrpc method that is used by ns_server update external
// cbauth state.
func (s *Svc) UpdateDBExt(c *CacheExt, outparam *bool) error {
	if outparam != nil {
		*outparam = true
	}
	db := s.cacheToCredsDBExt(c)
	s.l.Lock()
	updateDBLocked(s, db)
	s.l.Unlock()
	return nil
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
	cfgChanges := s.needConfigRefresh(db)
	updateDBLocked(s, db)
	s.l.Unlock()
	if cfgChanges != 0 {
		s.tlsNotifier.notifyTLSChange()
		s.cfgChangeNotifier.notifyCfgChange(cfgChanges)
	}
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

// NewSVCForTest constructs Svc instance.
func NewSVCForTest(period time.Duration, staleErr error, waitfn func(time.Duration, chan struct{}, func())) *Svc {
	if staleErr == nil {
		panic("staleErr must be non-nil")
	}

	s := &Svc{
		staleErr:          staleErr,
		semaphore:         make(semaphore, 10),
		tlsNotifier:       newTLSNotifier(),
		cfgChangeNotifier: newCfgChangeNotifier(),
	}

	dt, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		panic("http.DefaultTransport not an *http.Transport")
	}
	tr := &http.Transport{
		Proxy:                 dt.Proxy,
		DialContext:           dt.DialContext,
		MaxIdleConns:          dt.MaxIdleConns,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       dt.IdleConnTimeout,
		ExpectContinueTimeout: dt.ExpectContinueTimeout,
	}
	SetTransport(s, tr)

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

	go s.tlsNotifier.loop()
	go s.cfgChangeNotifier.loop()
	return s
}

// SetTransport allows to change RoundTripper for Svc
func SetTransport(s *Svc, rt http.RoundTripper) {
	s.httpClient = &http.Client{Transport: rt}
}

func (s *Svc) SetConnectInfo(hostport, user, password string) {
	s.hostport = hostport
	s.user = user
	s.password = password
}

func (s *Svc) buildUrl(uri string) string {
	return "http://" + s.hostport + uri
}

func (s *Svc) needConfigRefresh(db *credsDB) uint64 {
	var changes uint64 = 0
	if s.db == nil {
		return _MAX_CFG_CHANGE_FLAGS - 1
	}

	if s.db.certVersion != db.certVersion ||
		!reflect.DeepEqual(s.db.tlsConfig, db.tlsConfig) {
		changes |= CFG_CHANGE_CERTS_TLSCONFIG
	}

	if s.db.clusterEncryptionConfig != db.clusterEncryptionConfig {
		changes |= CFG_CHANGE_CLUSTER_ENCRYPTION
	}

	if s.db.limitsConfig != db.limitsConfig {
		changes |= CFG_CHANGE_USER_LIMITS
	}

	return changes
}

func fetchDB(s *Svc) *credsDB {
	s.l.RLock()
	db := s.db
	c := s.freshChan
	s.l.RUnlock()

	if db != nil || c == nil {
		return db
	}

	// if db is stale try to wait a bit
	<-c
	// double receive doesn't change anything from correctness
	// standpoint (we close channel), but helps a lot for tests
	<-c
	s.l.RLock()
	db = s.db
	s.l.RUnlock()

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

func verifyPasswordOnServer(s *Svc, user, password string) (*CredsImpl, error) {
	req, err := http.NewRequest("GET", "http://host/", nil)
	if err != nil {
		panic("Must not happen: " + err.Error())
	}
	req.SetBasicAuth(user, password)
	return VerifyOnServer(s, req.Header)
}

// VerifyOnBehalf authenticates http request with on behalf header
func VerifyOnBehalf(s *Svc, user, password, onBehalfUser,
	onBehalfDomain string) (*CredsImpl, error) {

	db := fetchDB(s)
	if db == nil {
		return nil, staleError(s)
	}

	if verifySpecialCreds(db, user, password) {
		return &CredsImpl{
			name:   onBehalfUser,
			s:      s,
			domain: onBehalfDomain}, nil
	}
	return nil, ErrNoAuth
}

// VerifyOnServer authenticates http request by calling POST /_cbauth REST endpoint
func VerifyOnServer(s *Svc, reqHeaders http.Header) (*CredsImpl, error) {
	db := fetchDB(s)
	if db == nil {
		return nil, staleError(s)
	}

	if s.db.authCheckURL == "" {
		return nil, ErrNoAuth
	}

	s.semaphore.wait()
	defer s.semaphore.signal()

	req, err := http.NewRequest("POST", db.authCheckURL, nil)
	if err != nil {
		panic(err)
	}

	copyHeader(tokenHeader, reqHeaders, req.Header)
	copyHeader("ns-server-auth-token", reqHeaders, req.Header)
	copyHeader("Cookie", reqHeaders, req.Header)
	copyHeader("Authorization", reqHeaders, req.Header)

	rv, err := executeReqAndGetCreds(s, req)
	if err != nil {
		return nil, err
	}

	return rv, nil
}

func executeReqAndGetCreds(s *Svc, req *http.Request) (*CredsImpl, error) {
	hresp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer hresp.Body.Close()
	defer io.Copy(ioutil.Discard, hresp.Body)

	if hresp.StatusCode == 401 {
		return nil, ErrNoAuth
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
		User, Domain, Uuid string
	}{}
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return nil, err
	}

	rv := CredsImpl{name: resp.User, domain: resp.Domain, uuid: resp.Uuid, s: s}
	return &rv, nil
}

type serviceLimits struct {
	version string
	user    string
	domain  string
	service string
}

func GetUserLimits(s *Svc, user, domain, service string) (map[string]int, error) {
	var limits = map[string]int{}
	if domain != "local" {
		return limits, nil
	}

	db := fetchDB(s)
	if db == nil {
		return limits, staleError(s)
	}

	s.ulCacheOnce.Do(func() { s.ulCache = utils.NewCache(1024) })

	key := serviceLimits{db.limitsConfig.UserLimitsVersion, user, domain, service}

	cachedlimits, found := s.ulCache.Get(key)
	limits, ok := cachedlimits.(map[string]int)
	if found && ok {
		return limits, nil
	}

	limits, err := getUserLimitsOnServer(s, db, user, domain, service)
	if err != nil {
		return limits, err
	}
	s.ulCache.Add(key, limits)
	return limits, nil
}

func getUserLimitsOnServer(s *Svc, db *credsDB, user, domain, service string) (map[string]int, error) {
	s.semaphore.wait()
	defer s.semaphore.signal()

	var limits = map[string]int{}
	req, err := http.NewRequest("GET", db.limitsCheckURL, nil)
	if err != nil {
		return limits, err
	}
	req.SetBasicAuth(db.specialUser, db.specialPassword)

	v := url.Values{}
	v.Set("user", user)
	v.Set("domain", domain)
	v.Set("service", service)
	req.URL.RawQuery = v.Encode()

	hresp, err := s.httpClient.Do(req)
	if err != nil {
		return limits, err
	}
	defer hresp.Body.Close()
	defer io.Copy(ioutil.Discard, hresp.Body)

	switch hresp.StatusCode {
	case 200:
		body, readErr := ioutil.ReadAll(hresp.Body)
		if readErr != nil {
			return limits, fmt.Errorf("Unexpected readErr %v", readErr)
		}
		jsonErr := json.Unmarshal(body, &limits)
		if jsonErr != nil {
			return limits, fmt.Errorf("Unexpected json unmarshal error %v", jsonErr)
		}
		return limits, nil
	}
	return limits, fmt.Errorf("Unexpected return code %v", hresp.StatusCode)
}

type userUUID struct {
	version string
	user    string
	domain  string
}

func GetUserUuid(s *Svc, user, domain string) (string, error) {
	if domain != "local" {
		return "", ErrNoUuid
	}

	db := fetchDB(s)
	if db == nil {
		return "", staleError(s)
	}

	s.uuidCacheOnce.Do(func() { s.uuidCache = utils.NewCache(256) })

	key := userUUID{db.userVersion, user, domain}

	cachedUuid, found := s.uuidCache.Get(key)
	if found {
		return cachedUuid.(string), nil
	}

	uuid, err := getUserUuidOnServer(s, db, user, domain)
	if err != nil {
		return "", err
	}
	s.uuidCache.Add(key, uuid)
	return uuid, nil
}

func getUserUuidOnServer(s *Svc, db *credsDB, user, domain string) (string, error) {
	s.semaphore.wait()
	defer s.semaphore.signal()

	req, err := http.NewRequest("GET", db.uuidCheckURL, nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(db.specialUser, db.specialPassword)

	v := url.Values{}
	v.Set("user", user)
	v.Set("domain", domain)
	req.URL.RawQuery = v.Encode()

	hresp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer hresp.Body.Close()
	defer io.Copy(ioutil.Discard, hresp.Body)

	if hresp.StatusCode != 200 {
		err = fmt.Errorf("Expecting 200 from ns_server uuid endpoint. Got: %s", hresp.Status)
		return "", err
	}

	body, readErr := ioutil.ReadAll(hresp.Body)
	if readErr != nil {
		return "", fmt.Errorf("Unexpected readErr %v", readErr)
	}
	resp := struct {
		User, Domain, Uuid string
	}{}
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return "", fmt.Errorf("Unexpected json unmarshal error %v", err)
	}

	if resp.Uuid == "" {
		return "", ErrNoUuid
	}
	return resp.Uuid, nil
}

type userPermission struct {
	version    string
	user       string
	domain     string
	permission string
}

func checkPermission(s *Svc, user, domain, permission string) (bool, error) {
	db := fetchDB(s)
	if db == nil {
		return false, staleError(s)
	}

	s.upCacheOnce.Do(func() { s.upCache = utils.NewCache(1024) })

	if domain == "external" {
		return checkPermissionOnServer(s, db, user, domain, permission)
	}

	key := userPermission{db.permissionsVersion, user, domain, permission}

	allowed, found := s.upCache.Get(key)
	if found {
		return allowed.(bool), nil
	}

	allowedOnServer, err := checkPermissionOnServer(s, db, user, domain, permission)
	if err != nil {
		return false, err
	}
	s.upCache.Add(key, allowedOnServer)
	return allowedOnServer, nil
}

func checkPermissionOnServer(s *Svc, db *credsDB, user, domain, permission string) (bool, error) {
	s.semaphore.wait()
	defer s.semaphore.signal()

	req, err := http.NewRequest("GET", db.permissionCheckURL, nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(db.specialUser, db.specialPassword)

	v := url.Values{}
	v.Set("user", user)
	v.Set("domain", domain)
	v.Set("permission", permission)
	req.URL.RawQuery = v.Encode()

	hresp, err := s.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer hresp.Body.Close()
	defer io.Copy(ioutil.Discard, hresp.Body)

	switch hresp.StatusCode {
	case 200:
		return true, nil
	case 401:
		return false, nil
	}
	return false, fmt.Errorf("Unexpected return code %v", hresp.StatusCode)
}

type userPassword struct {
	version  string
	user     string
	password string
}

type userInfo struct {
	user   string
	domain string
	uuid   string
}

// VerifyPassword verifies given user/password creds against cbauth
// password database. Returns nil, nil if given creds are not
// recognised at all.
func VerifyPassword(s *Svc, user, password string) (*CredsImpl, error) {
	db := fetchDB(s)
	if db == nil {
		return nil, staleError(s)
	}

	if verifySpecialCreds(db, user, password) {
		return &CredsImpl{
			name:     user,
			password: password,
			s:        s,
			domain:   "admin"}, nil
	}

	s.authCacheOnce.Do(func() { s.authCache = utils.NewCache(256) })

	key := userPassword{db.authVersion, user, password}

	id, found := s.authCache.Get(key)
	if found {
		identity := id.(userInfo)
		return &CredsImpl{
			name:     identity.user,
			password: password,
			s:        s,
			uuid:     identity.uuid,
			domain:   identity.domain}, nil
	}

	rv, err := verifyPasswordOnServer(s, user, password)
	if err != nil {
		return nil, err
	}

	if rv.domain == "admin" || rv.domain == "local" {
		s.authCache.Add(key, userInfo{rv.name, rv.domain, rv.uuid})
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

// RegisterTLSRefreshCallback registers callback for refreshing TLS config
func RegisterTLSRefreshCallback(s *Svc, callback TLSRefreshCallback) error {
	return s.tlsNotifier.registerCallback(callback)
}

// RegisterConfigRefreshCallback registers callback for refreshing SSL certs
// or TLS config.
func RegisterConfigRefreshCallback(s *Svc, cb ConfigRefreshCallback) error {
	return s.cfgChangeNotifier.registerCallback(cb)
}

// GetClientCertAuthType returns TLS cert type
func GetClientCertAuthType(s *Svc) (tls.ClientAuthType, error) {
	db := fetchDB(s)
	if db == nil {
		return tls.NoClientCert, staleError(s)
	}

	return db.tlsConfig.ClientAuthType, nil
}

// GetLimitsConfig returns limits settings.
func GetLimitsConfig(s *Svc) (LimitsConfig, error) {
	db := fetchDB(s)
	if db == nil {
		return LimitsConfig{}, staleError(s)
	}

	return db.limitsConfig, nil
}

// GetClusterEncryptionConfig returns if cross node communication needs to be
// encrypted and if non-SSL ports need to be disabled.
func GetClusterEncryptionConfig(s *Svc) (ClusterEncryptionConfig, error) {
	db := fetchDB(s)
	if db == nil {
		return ClusterEncryptionConfig{}, staleError(s)
	}

	return db.clusterEncryptionConfig, nil
}

func importTLSConfig(cfg *tlsConfigImport, ClientCertAuthState string) TLSConfig {
	return TLSConfig{
		MinVersion:               minTLSVersion(cfg.MinTLSVersion),
		CipherSuites:             append([]uint16{}, cfg.Ciphers...),
		CipherSuiteNames:         append([]string{}, cfg.CipherNames...),
		CipherSuiteOpenSSLNames:  append([]string{}, cfg.CipherOpenSSLNames...),
		PreferServerCipherSuites: cfg.CipherOrder,
		ClientAuthType:           getAuthType(ClientCertAuthState),
		present:                  cfg.Present,
		PrivateKeyPassphrase:     cfg.PrivateKeyPassphrase,
	}
}

// GetTLSConfig returns current tls config that contains cipher suites,
// min TLS version, etc.
func GetTLSConfig(s *Svc) (TLSConfig, error) {
	db := fetchDB(s)
	if db == nil {
		return TLSConfig{}, staleError(s)
	}
	if !db.tlsConfig.present {
		return TLSConfig{}, fmt.Errorf("TLSConfig is not present for this service")
	}
	return db.tlsConfig, nil
}

func minTLSVersion(str string) uint16 {
	switch strings.ToLower(str) {
	case "tlsv1":
		return tls.VersionTLS10
	case "tlsv1.1":
		return tls.VersionTLS11
	case "tlsv1.2":
		return tls.VersionTLS12
	case "tlsv1.3":
		// return tls.VersionTLS13
		// Ideally we want the code above but then cbauth gets compiled with
		// multiple versions of GO so we cannot rely on the const
		// VersionTLS13 to be present.
		return 0x0304
	default:
		return tls.VersionTLS10
	}
}

func getAuthType(state string) tls.ClientAuthType {
	if state == "enable" {
		return tls.VerifyClientCertIfGiven
	} else if state == "mandatory" {
		return tls.RequireAndVerifyClientCert
	} else {
		return tls.NoClientCert
	}
}

type clienCertHash struct {
	hash    string
	version string
}

// MaybeGetCredsFromCert extracts user's credentials from certificate
// Those returned credentials could be used for calling IsAllowed function
func MaybeGetCredsFromCert(s *Svc, req *http.Request) (*CredsImpl, error) {
	db := fetchDB(s)
	if db == nil {
		return nil, staleError(s)
	}

	// If TLS is nil, then do nothing as it's an http request and not https.
	if req.TLS == nil {
		return nil, nil
	}

	s.clientCertCacheOnce.Do(func() {
		s.clientCertCache = utils.NewCache(256)
	})
	cAuthType := db.tlsConfig.ClientAuthType

	if cAuthType == tls.NoClientCert {
		return nil, nil
	} else if cAuthType == tls.VerifyClientCertIfGiven && len(req.TLS.PeerCertificates) == 0 {
		return nil, nil
	} else {
		// The leaf certificate is the one which will have the username
		// encoded into it and it's the first entry in 'PeerCertificates'.
		cert := req.TLS.PeerCertificates[0]

		h := md5.New()
		h.Write(cert.Raw)
		key := clienCertHash{
			hash:    string(h.Sum(nil)),
			version: db.clientCertAuthVersion,
		}

		val, found := s.clientCertCache.Get(key)
		if found {
			ui, _ := val.(*userInfo)
			creds := &CredsImpl{
				name:   ui.user,
				domain: ui.domain,
				uuid:   ui.uuid,
				s:      s,
			}
			return creds, nil
		}

		creds, _ := getUserIdentityFromCert(cert, db, s)
		if creds != nil {
			ui := &userInfo{
				user:   creds.name,
				domain: creds.domain,
				uuid:   creds.uuid,
			}
			s.clientCertCache.Add(key, interface{}(ui))
			return creds, nil
		}

		return nil, ErrUserNotFound
	}
}

func getUserIdentityFromCert(cert *x509.Certificate, db *credsDB, s *Svc) (*CredsImpl, error) {
	if db.authCheckURL == "" {
		return nil, ErrNoAuth
	}

	s.semaphore.wait()
	defer s.semaphore.signal()

	req, err := http.NewRequest("POST", db.extractUserFromCertURL, bytes.NewReader(cert.Raw))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/octet-stream")
	req.SetBasicAuth(db.specialUser, db.specialPassword)

	rv, err := executeReqAndGetCreds(s, req)
	if err != nil {
		return nil, err
	}

	return rv, nil
}

// GetNodeUuid returns UUID of the node cbauth is currently connecting to
func GetNodeUuid(s *Svc) (string, error) {
	db := fetchDB(s)
	if db == nil {
		return "", staleError(s)
	}
	return db.nodeUUID, nil
}
