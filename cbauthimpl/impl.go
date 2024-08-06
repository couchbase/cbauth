// @author Couchbase <info@couchbase.com>
// @copyright 2015-2023 Couchbase, Inc.
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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/couchbase/cbauth/httpreq"
	"github.com/couchbase/cbauth/utils"
)

// TLSRefreshCallback type describes callback for reinitializing TLSConfig when ssl certificate
// or client cert auth setting changes.
type TLSRefreshCallback func() error

const (
	CFG_CHANGE_CERTS_TLSCONFIG uint64 = 1 << iota
	CFG_CHANGE_CLUSTER_ENCRYPTION
	CFG_CHANGE_CLIENT_CERTS_TLSCONFIG
	CFG_CHANGE_GUARDRAIL_STATUSES
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
	MinVersion                 uint16
	CipherSuites               []uint16
	CipherSuiteNames           []string
	CipherSuiteOpenSSLNames    []string
	PreferServerCipherSuites   bool
	ClientAuthType             tls.ClientAuthType
	present                    bool
	PrivateKeyPassphrase       []byte
	ClientPrivateKeyPassphrase []byte
}

// ClusterEncryptionConfig contains info about whether to use SSL ports for
// communication channels and whether to disable non-SSL ports.
type ClusterEncryptionConfig struct {
	EncryptData        bool
	DisableNonSSLPorts bool
}

type tlsConfigImport struct {
	MinTLSVersion              string
	Ciphers                    []uint16
	CipherNames                []string
	CipherOpenSSLNames         []string
	CipherOrder                bool
	Present                    bool
	PrivateKeyPassphrase       []byte
	ClientPrivateKeyPassphrase []byte
}

type CacheConfig struct {
	UuidCacheSize       int `json:"uuidCacheSize"`
	UserBktsCacheSize   int `json:"userBktsCacheSize"`
	UpCacheSize         int `json:"upCacheSize"`
	AuthCacheSize       int `json:"authCacheSize"`
	ClientCertCacheSize int `json:"clientCertCacheSize"`
}


// GuardrailStatus contains the current status for a resource that we want
// a service to be aware of.
// Severity may be one of the following, in ascending order of severity:
// - "serious"
// - "critical"
// - "maximum" (equivalently known as "Critical Enforcement")
type GuardrailStatus struct {
	Resource string `json:"resource"`
	Severity string `json:"severity"`
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

const uaCbauthSuffix = "cbauth"
const uaCbauthVersion = ""

var userAgent = utils.MakeUserAgent(uaCbauthSuffix, uaCbauthVersion)

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
	clusterUUID             string
	nodeUUID                string
	nodes                   []Node
	authCheckURL            string
	permissionCheckURL      string
	uuidCheckURL            string
	userBucketsURL          string
	specialUser             string
	specialPasswords        []string
	permissionsVersion      string
	userVersion             string
	authVersion             string
	certVersion             int
	clientCertVersion       int
	extractUserFromCertURL  string
	clientCertAuthVersion   string
	clusterEncryptionConfig ClusterEncryptionConfig
	tlsConfig               TLSConfig
	lastHeard               time.Time
	cacheConfig             CacheConfig
	guardrailStatuses       []GuardrailStatus
}

// Cache is a structure into which the revrpc json is unmarshalled
type Cache struct {
	Nodes                   []Node
	AuthCheckURL            string `json:"authCheckUrl"`
	PermissionCheckURL      string `json:"permissionCheckUrl"`
	UuidCheckURL            string
	UserBucketsURL          string
	SpecialUser             string   `json:"specialUser"`
	SpecialPasswords        []string `json:"specialPasswords"`
	PermissionsVersion      string
	UserVersion             string
	AuthVersion             string
	CertVersion             int
	ClientCertVersion       int
	ExtractUserFromCertURL  string                  `json:"extractUserFromCertURL"`
	ClientCertAuthState     string                  `json:"clientCertAuthState"`
	ClientCertAuthVersion   string                  `json:"clientCertAuthVersion"`
	ClusterEncryptionConfig ClusterEncryptionConfig `json:"clusterEncryptionConfig"`
	TLSConfig               tlsConfigImport         `json:"tlsConfig"`
	CacheConfig             CacheConfig             `json:"cacheConfig"`
	GuardrailStatuses       []GuardrailStatus       `json:"guardrailStatuses"`
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
	ClusterUUID                 string
}

// Void is a structure that represents empty revrpc payload
type Void *struct{}

// CredsImpl implements cbauth.Creds interface.
type CredsImpl struct {
	name     string
	domain   string
	s        *Svc
}

type CacheStats struct {
	Name    string `json:"name"`
	MaxSize int    `json:"maxSize"`
	Size    int    `json:"size"`
	Hit     uint64 `json:"hit"`
	Miss    uint64 `json:"miss"`
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

// IsAllowed method returns true if the permission is granted
// for these credentials
func (c *CredsImpl) IsAllowed(permission string) (bool, error) {
	return checkPermission(c.s, c.name, c.domain, permission, true)
}

// IsAllowedInternal method returns true if the permission is
// granted for these credentials
func (c *CredsImpl) IsAllowedInternal(permission string) (bool, error) {
	return checkPermission(c.s, c.name, c.domain, permission, false)
}

func verifySpecialCreds(db *credsDB, user, password string) bool {
	if len(user) == 0 || user[0] != '@' {
		return false
	}
	for _, sp := range db.specialPasswords {
		if password == sp {
			return true
		}
	}
	return false
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
	uuidCache           ReqCache
	userBktsCache       ReqCache
	upCache             ReqCache
	authCache           *utils.Cache
	authCacheOnce       sync.Once
	clientCertCache     *utils.Cache
	clientCertCacheOnce sync.Once
	httpClient          *http.Client
	semaphore           semaphore
	tlsNotifier         *tlsNotifier
	cfgChangeNotifier   *cfgChangeNotifier
	hostport            string
	user                string
	password            string
	heartbeatInterval   int
	heartbeatWait       int
	clusterUUID         string
}

// Cache sizes should come from ns_server. But in case they are not, we need to
// have some defaults for them.
const defaultUuidCacheSize = 256
const defaultUserBktsCacheSize = 1024
const defaultUpCacheSize = 1024
const defaultAuthCacheSize = 256
const defaultClientCertCacheSize = 256

func cacheToCredsDB(c *Cache) (db *credsDB) {
	db = &credsDB{
		nodes:                   c.Nodes,
		authCheckURL:            c.AuthCheckURL,
		permissionCheckURL:      c.PermissionCheckURL,
		uuidCheckURL:            c.UuidCheckURL,
		userBucketsURL:          c.UserBucketsURL,
		specialUser:             c.SpecialUser,
		specialPasswords:        c.SpecialPasswords,
		permissionsVersion:      c.PermissionsVersion,
		userVersion:             c.UserVersion,
		authVersion:             c.AuthVersion,
		certVersion:             c.CertVersion,
		clientCertVersion:       c.ClientCertVersion,
		extractUserFromCertURL:  c.ExtractUserFromCertURL,
		clientCertAuthVersion:   c.ClientCertAuthVersion,
		clusterEncryptionConfig: c.ClusterEncryptionConfig,
		tlsConfig:               importTLSConfig(&c.TLSConfig, c.ClientCertAuthState),
		cacheConfig:             c.CacheConfig,
		guardrailStatuses:       c.GuardrailStatuses,
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
		specialPasswords:      []string{s.password},
		tlsConfig:             tlsConfig,
		nodeUUID:              c.NodeUUID,
		clusterUUID:           c.ClusterUUID,
		lastHeard:             time.Now(),
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
	// if the user did not specify a cluster uuid, use the one from the response
	if s.clusterUUID == "" {
		s.clusterUUID = db.clusterUUID
	}
	// if there is a cluster uuid, it needs to match the one already stored
	if db.clusterUUID != "" && s.clusterUUID != db.clusterUUID {
		db = nil
	}
	updateDBLocked(s, db)
	s.l.Unlock()
	return nil
}

func (s *Svc) Heartbeat(Void, outparam *Void) error {
	if outparam != nil {
		*outparam = nil
	}
	s.l.Lock()
	if s.db != nil {
		s.db.lastHeard = time.Now()
	}
	s.l.Unlock()
	return nil
}

func updateCacheSize(s *Svc, db *credsDB) {
	if s.db == nil {
		return
	}
	if s.db.cacheConfig != db.cacheConfig {
		if s.uuidCache.cache != nil {
			s.uuidCache.cache.UpdateSize(db.cacheConfig.UuidCacheSize)
		}
		if s.userBktsCache.cache != nil {
			s.userBktsCache.cache.UpdateSize(db.cacheConfig.UserBktsCacheSize)
		}
		if s.upCache.cache != nil {
			s.upCache.cache.UpdateSize(db.cacheConfig.UpCacheSize)
		}
		if s.authCache != nil {
			s.authCache.UpdateSize(db.cacheConfig.AuthCacheSize)
		}
		if s.clientCertCache != nil {
			s.clientCertCache.UpdateSize(db.cacheConfig.ClientCertCacheSize)
		}
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
	cfgChanges := s.needConfigRefresh(db)
	updateCacheSize(s, db)
	updateDBLocked(s, db)
	s.l.Unlock()
	if cfgChanges != 0 {
		s.tlsNotifier.notifyTLSChange()
		s.cfgChangeNotifier.notifyCfgChange(cfgChanges)
	}
	return nil
}

type CachesStats struct {
	CacheStats []CacheStats `json:"cacheStats"`
}

func (s *Svc) GetStats(Void, outparam *CachesStats) error {

	if outparam == nil {
		return nil
	}

	cacheStats := []CacheStats{}

	stats := getCacheStats("uuid_cache", s.uuidCache.cache)
	cacheStats = append(cacheStats, *stats)

	stats = getCacheStats("user_bkts_cache", s.userBktsCache.cache)
	cacheStats = append(cacheStats, *stats)

	stats = getCacheStats("up_cache", s.upCache.cache)
	cacheStats = append(cacheStats, *stats)

	stats = getCacheStats("auth_cache", s.authCache)
	cacheStats = append(cacheStats, *stats)

	stats = getCacheStats("client_cert_cache", s.clientCertCache)
	cacheStats = append(cacheStats, *stats)

	(*outparam).CacheStats = cacheStats

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
	if s.db != nil {
		return errors.New("Didn't hear from server for a while")
	}
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
		heartbeatInterval: 0,
		heartbeatWait:     0,
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

func (s *Svc) SetConnectInfo(hostport, user, password string,
	heartbeatInterval, heartbeatWait int) {
	s.hostport = hostport
	s.user = user
	s.password = password
	s.heartbeatInterval = heartbeatInterval
	s.heartbeatWait = heartbeatWait
}

func (s *Svc) buildUrl(uri string) string {
	return "http://" + s.hostport + uri
}

func (s *Svc) needConfigRefresh(db *credsDB) uint64 {
	var changes uint64 = 0
	if s.db == nil {
		return _MAX_CFG_CHANGE_FLAGS - 1
	}

	if s.serverTLSSettingsChanged(db) {
		changes |= CFG_CHANGE_CERTS_TLSCONFIG
	}

	if s.clientTLSSettingsChanged(db) {
		changes |= CFG_CHANGE_CLIENT_CERTS_TLSCONFIG
	}

	if s.db.clusterEncryptionConfig != db.clusterEncryptionConfig {
		changes |= CFG_CHANGE_CLUSTER_ENCRYPTION
	}

	if s.guardrailStatusesChanged(db) {
		changes |= CFG_CHANGE_GUARDRAIL_STATUSES
	}

	return changes
}

func (s *Svc) serverTLSSettingsChanged(db *credsDB) bool {
	return s.db.certVersion != db.certVersion ||
		s.db.tlsConfig.MinVersion != db.tlsConfig.MinVersion ||
		!reflect.DeepEqual(s.db.tlsConfig.CipherSuites,
			db.tlsConfig.CipherSuites) ||
		s.db.tlsConfig.PreferServerCipherSuites !=
			db.tlsConfig.PreferServerCipherSuites ||
		s.db.tlsConfig.ClientAuthType != db.tlsConfig.ClientAuthType ||
		!reflect.DeepEqual(s.db.tlsConfig.PrivateKeyPassphrase,
			db.tlsConfig.PrivateKeyPassphrase)
}

func (s *Svc) clientTLSSettingsChanged(db *credsDB) bool {
	return s.db.clientCertVersion != db.clientCertVersion ||
		!reflect.DeepEqual(s.db.tlsConfig.ClientPrivateKeyPassphrase,
			db.tlsConfig.ClientPrivateKeyPassphrase)
}

func (s *Svc) guardrailStatusesChanged(db *credsDB) bool {
	return !reflect.DeepEqual(s.db.guardrailStatuses,
		db.guardrailStatuses)
}

func fetchDB(s *Svc) *credsDB {
	s.l.RLock()
	db := s.db
	c := s.freshChan
	s.l.RUnlock()

	if db != nil || c == nil {
		return s.ifNotExpired(db)
	}

	// if db is stale try to wait a bit
	<-c
	// double receive doesn't change anything from correctness
	// standpoint (we close channel), but helps a lot for tests
	<-c
	s.l.RLock()
	db = s.db
	s.l.RUnlock()

	return s.ifNotExpired(db)
}

func (s *Svc) ifNotExpired(db *credsDB) *credsDB {
	if db != nil && s.heartbeatInterval != 0 &&
		int(time.Since(db.lastHeard).Seconds()) > s.heartbeatWait {
		return nil
	}

	return db
}

const tokenHeader = "ns-server-ui"

// IsAuthTokenPresent returns true iff ns_server's ui token header
// ("ns-server-ui") is set to "yes". UI is using that header to
// indicate that request is using so called token auth.
func IsAuthTokenPresent(Hdr httpreq.HttpHeader) bool {
	return Hdr.Get(tokenHeader) == "yes"
}

func copyHeader(name string, from httpreq.HttpHeader, to http.Header) {
	if val := from.Get(name); val != "" {
		to.Set(name, val)
	}
}

func maybeSetClusterUUID(s *Svc, v *url.Values) {
	if s.clusterUUID != "" {
		v.Set("uuid", s.clusterUUID)
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

	creds, err := VerifyPassword(s, user, password)
	if err != nil {
		return nil, err
	}

	allowed, err := creds.IsAllowed(
		"cluster.admin.security.admin!impersonate")
	if err != nil {
		return nil, err
	}
	if allowed {
		return &CredsImpl{
			name:   onBehalfUser,
			s:      s,
			domain: onBehalfDomain}, nil
	}
	return nil, ErrNoAuth
}

// VerifyOnServer authenticates http request by calling POST /_cbauth REST endpoint
func VerifyOnServer(s *Svc, reqHeaders httpreq.HttpHeader) (*CredsImpl, error) {
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

	keys := []string{tokenHeader, "ns-server-auth-token",
		"Cookie", "Authorization"}
	for _, key := range keys {
		copyHeader(key, reqHeaders, req.Header)
	}

	req.Header.Set("User-Agent", userAgent)

	rv, err := executeReqAndGetCreds(s, req)
	if err != nil {
		return nil, err
	}

	return rv, nil
}

func executeReqAndGetCreds(s *Svc, req *http.Request) (*CredsImpl, error) {
	v := url.Values{}
	maybeSetClusterUUID(s, &v)
	req.URL.RawQuery = v.Encode()

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
		User, Domain string
	}{}
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return nil, err
	}

	rv := CredsImpl{name: resp.User, domain: resp.Domain, s: s}
	return &rv, nil
}

type ReqCache struct {
	cache     *utils.Cache
	cacheOnce sync.Once
}

type CacheParams struct {
	cache *ReqCache
	key   interface{}
	size  int
}

type processResponse func(*http.Response) (interface{}, error)

type ReqParams struct {
	respCallback processResponse
	url          string
	user         string
	domain       string
	service      string
	permission   string
	audit        bool
}

func getFromServer(s *Svc, db *credsDB, params *ReqParams) (interface{}, error) {
	s.semaphore.wait()
	defer s.semaphore.signal()

	req, err := http.NewRequest("GET", params.url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)

	if len(db.specialPasswords) > 0 {
		req.SetBasicAuth(db.specialUser, db.specialPasswords[0])
	}

	v := url.Values{}
	v.Set("user", params.user)
	v.Set("domain", params.domain)
	v.Set("audit", strconv.FormatBool(params.audit))
	if params.service != "" {
		v.Set("service", params.service)
	}
	if params.permission != "" {
		v.Set("permission", params.permission)
	}
	maybeSetClusterUUID(s, &v)
	req.URL.RawQuery = v.Encode()

	hresp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer hresp.Body.Close()
	defer io.Copy(ioutil.Discard, hresp.Body)

	val, err := params.respCallback(hresp)

	return val, err
}

// GET response callback for GetUserUuid
func processResponseUuid(resp *http.Response) (interface{}, error) {
	if resp.StatusCode == 200 {
		body, readErr := ioutil.ReadAll(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("Unexpected readErr %v", readErr)
		}
		uuidResp := struct {
			User, Domain, Uuid string
		}{}
		jsonErr := json.Unmarshal(body, &uuidResp)
		if jsonErr != nil {
			return nil, fmt.Errorf("Unexpected json unmarshal error %v", jsonErr)
		}
		if uuidResp.Uuid == "" {
			return nil, ErrNoUuid
		}
		return uuidResp.Uuid, nil
	}

	return nil, fmt.Errorf("Unexpected return code %v", resp.StatusCode)
}

// GET response callback for GetUserBuckets
func processResponseUserBuckets(resp *http.Response) (interface{}, error) {
	var bucketAndPerms = []string{}

	if resp.StatusCode == 200 {
		body, readErr := ioutil.ReadAll(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("Unexpected readErr %v", readErr)
		}
		jsonErr := json.Unmarshal(body, &bucketAndPerms)
		if jsonErr != nil {
			return nil, fmt.Errorf("Unexpected json unmarshal error %v", jsonErr)
		}
		return bucketAndPerms, nil
	}

	return nil, fmt.Errorf("Unexpected return code %v", resp.StatusCode)
}

// GET response callback for IsAllowed
func processResponsePermission(resp *http.Response) (interface{}, error) {
	switch resp.StatusCode {
	case 200:
		return true, nil
	case 401:
		return false, nil
	}

	return nil, fmt.Errorf("Unexpected return code %v", resp.StatusCode)
}

// Handles GetUserBuckets, GetUserUuid, IsAllowed GET requests
func handleGetRequest(s *Svc, db *credsDB, reqParams *ReqParams,
	cacheParams *CacheParams) (interface{}, error) {
	if cacheParams != nil {
		cacheParams.cache.cacheOnce.Do(
			func() {
				cacheParams.cache.cache = utils.NewCache(cacheParams.size)
			})

		cachedVal, found := cacheParams.cache.cache.Get(cacheParams.key)
		if found {
			return cachedVal, nil
		}
	}

	val, err := getFromServer(s, db, reqParams)
	if err == nil && cacheParams != nil {
		cacheParams.cache.cache.Add(cacheParams.key, val)
	}

	return val, err
}

type userUUID struct {
	version string
	user    string
	domain  string
}

func GetUserUuid(s *Svc, user, domain string) (string, error) {
	uuid := ""
	if domain != "local" {
		return uuid, ErrNoUuid
	}

	db := fetchDB(s)
	if db == nil {
		return uuid, staleError(s)
	}

	reqParams := &ReqParams{
		respCallback: processResponseUuid,
		url:          db.uuidCheckURL,
		user:         user,
		domain:       domain,
		audit:        true,
	}

	cacheSize := db.cacheConfig.UuidCacheSize
	if cacheSize == 0 {
		cacheSize = defaultUuidCacheSize
	}

	cacheParams := &CacheParams{
		cache: &s.uuidCache,
		key:   userUUID{db.userVersion, user, domain},
		size:  cacheSize,
	}

	val, err := handleGetRequest(s, db, reqParams, cacheParams)
	if err == nil {
		uuid = val.(string)
	}

	return uuid, err
}

type userBuckets struct {
	version string
	user    string
	domain  string
}

func GetUserBuckets(s *Svc, user, domain string) ([]string, error) {
	var bucketAndPerms = []string{}

	db := fetchDB(s)
	if db == nil {
		return bucketAndPerms, staleError(s)
	}

	reqParams := &ReqParams{
		respCallback: processResponseUserBuckets,
		url:          db.userBucketsURL,
		user:         user,
		domain:       domain,
		audit:        true,
	}

	cacheSize := db.cacheConfig.UserBktsCacheSize
	if cacheSize == 0 {
		cacheSize = defaultUserBktsCacheSize
	}

	cacheParams := &CacheParams{
		cache: &s.userBktsCache,
		key:   userBuckets{db.permissionsVersion, user, domain},
		size:  cacheSize,
	}

	val, err := handleGetRequest(s, db, reqParams, cacheParams)
	if err == nil {
		bucketAndPerms = val.([]string)
	}

	return bucketAndPerms, err
}

type userPermission struct {
	version    string
	user       string
	domain     string
	permission string
}

func checkPermission(s *Svc, user, domain, permission string, audit bool) (bool, error) {
	allowed := false

	db := fetchDB(s)
	if db == nil {
		return allowed, staleError(s)
	}

	reqParams := &ReqParams{
		respCallback: processResponsePermission,
		url:          db.permissionCheckURL,
		user:         user,
		domain:       domain,
		permission:   permission,
		audit:        audit,
	}

	var cacheParams *CacheParams

	if domain == "external" {
		cacheParams = nil
	} else {
		cacheSize := db.cacheConfig.UpCacheSize
		if cacheSize == 0 {
			cacheSize = defaultUpCacheSize
		}

		cacheParams = &CacheParams{
			cache: &s.upCache,
			key:   userPermission{db.permissionsVersion, user, domain, permission},
			size:  cacheSize,
		}
	}

	val, err := handleGetRequest(s, db, reqParams, cacheParams)
	if err == nil {
		allowed = val.(bool)
	}

	return allowed, err
}

type userPassword struct {
	version  string
	user     string
	password string
}

type userIdentity struct {
	user   string
	domain string
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
			s:        s,
			domain:   "admin"}, nil
	}

	cacheSize := db.cacheConfig.AuthCacheSize
	if cacheSize == 0 {
		cacheSize = defaultAuthCacheSize
	}

	s.authCacheOnce.Do(func() { s.authCache = utils.NewCache(cacheSize) })

	key := userPassword{db.authVersion, user, password}

	id, found := s.authCache.Get(key)
	if found {
		identity := id.(userIdentity)
		return &CredsImpl{
			name:     identity.user,
			s:        s,
			domain:   identity.domain}, nil
	}

	rv, err := verifyPasswordOnServer(s, user, password)
	if err != nil {
		return nil, err
	}

	if rv.domain == "admin" || rv.domain == "local" ||
		rv.domain == "stats_reader" {
		s.authCache.Add(key, userIdentity{rv.name, rv.domain})
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

// GetClusterEncryptionConfig returns if cross node communication needs to be
// encrypted and if non-SSL ports need to be disabled.
func GetClusterEncryptionConfig(s *Svc) (ClusterEncryptionConfig, error) {
	db := fetchDB(s)
	if db == nil {
		return ClusterEncryptionConfig{}, staleError(s)
	}

	return db.clusterEncryptionConfig, nil
}

// GetGuardrailStatuses returns guardrail statuses.
func GetGuardrailStatuses(s *Svc) ([]GuardrailStatus, error) {
	db := fetchDB(s)
	if db == nil {
		return []GuardrailStatus{}, staleError(s)
	}
	return db.guardrailStatuses, nil
}

func importTLSConfig(cfg *tlsConfigImport, ClientCertAuthState string) TLSConfig {
	return TLSConfig{
		MinVersion:                 minTLSVersion(cfg.MinTLSVersion),
		CipherSuites:               append([]uint16{}, cfg.Ciphers...),
		CipherSuiteNames:           append([]string{}, cfg.CipherNames...),
		CipherSuiteOpenSSLNames:    append([]string{}, cfg.CipherOpenSSLNames...),
		PreferServerCipherSuites:   cfg.CipherOrder,
		ClientAuthType:             getAuthType(ClientCertAuthState),
		present:                    cfg.Present,
		PrivateKeyPassphrase:       cfg.PrivateKeyPassphrase,
		ClientPrivateKeyPassphrase: cfg.ClientPrivateKeyPassphrase,
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
		return tls.VersionTLS12
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
func MaybeGetCredsFromCert(s *Svc, tlsState *tls.ConnectionState) (*CredsImpl, error) {
	db := fetchDB(s)
	if db == nil {
		return nil, staleError(s)
	}

	// If TLS is nil, then do nothing as it's an http request and not https.
	if tlsState == nil {
		return nil, nil
	}

	cacheSize := db.cacheConfig.ClientCertCacheSize
	if cacheSize == 0 {
		cacheSize = defaultClientCertCacheSize
	}

	s.clientCertCacheOnce.Do(func() {
		s.clientCertCache = utils.NewCache(cacheSize)
	})
	cAuthType := db.tlsConfig.ClientAuthType

	if cAuthType == tls.NoClientCert {
		return nil, nil
	} else if cAuthType == tls.VerifyClientCertIfGiven && len(tlsState.PeerCertificates) == 0 {
		return nil, nil
	} else {
		// The leaf certificate is the one which will have the username
		// encoded into it and it's the first entry in 'PeerCertificates'.
		cert := tlsState.PeerCertificates[0]

		h := md5.New()
		h.Write(cert.Raw)
		key := clienCertHash{
			hash:    string(h.Sum(nil)),
			version: db.clientCertAuthVersion,
		}

		val, found := s.clientCertCache.Get(key)
		if found {
			ui, _ := val.(*userIdentity)
			creds := &CredsImpl{name: ui.user, domain: ui.domain, s: s}
			return creds, nil
		}

		creds, _ := getUserIdentityFromCert(cert, db, s)
		if creds != nil {
			ui := &userIdentity{user: creds.name, domain: creds.domain}
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
	if len(db.specialPasswords) > 0 {
		req.SetBasicAuth(db.specialUser, db.specialPasswords[0])
	}

	req.Header.Set("User-Agent", userAgent)

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

// SetExpectedClusterUuid sets the expected UUID of the cluster we are connecting to
func SetExpectedClusterUuid(s *Svc, clusterUUID string) error {
	s.l.Lock()
	s.clusterUUID = clusterUUID
	s.l.Unlock()
	return nil
}

// GetClusterUuid returns UUID of the cluster cbauth is currently connecting to
func GetClusterUuid(s *Svc) (string, error) {
	db := fetchDB(s)
	if db == nil {
		return "", staleError(s)
	}
	return db.clusterUUID, nil
}

func getCacheStats(cname string, c *utils.Cache) (stats *CacheStats) {
	maxSize, size := 0, 0
	hit, miss := uint64(0), uint64(0)

	if c != nil {
		maxSize, size, hit, miss = c.GetStats()
	}

	stats = &CacheStats{
		Name:    cname,
		MaxSize: maxSize,
		Size:    size,
		Hit:     hit,
		Miss:    miss,
	}

	return
}
