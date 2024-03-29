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

package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"errors"

	"github.com/couchbase/cbauth"
	"github.com/couchbase/cbauth/utils"
	log "github.com/couchbase/clog"
)

var mgmtURLFlag string
var listenFlag string
var useFullerRequestFlag bool
var authFlag string
var externalFlag bool
var authU string
var authP string
var toolName string
var heartbeat int

const uaCbauthEgSuffix = "cbauth"
const uaCbauthEgVersion = ""

var userAgent = utils.MakeUserAgent(uaCbauthEgSuffix, uaCbauthEgVersion)

func initFlags() {
	flag.StringVar(&mgmtURLFlag, "mgmtURL", "", "base url of mgmt service (e.g. http://lh:8091/)")
	flag.StringVar(&listenFlag, "listen", "", "listen endpoint (e.g. :8080)")
	flag.BoolVar(&useFullerRequestFlag, "use-fuller-request", false, "")
	flag.BoolVar(&externalFlag, "external", false,
		"test cbauth for external clients")
	flag.StringVar(&authFlag, "auth", "", "user:password to use to initialize cbauth")
	flag.StringVar(&toolName, "name", "external-tool",
		"name of the external tool")
	flag.IntVar(&heartbeat, "heartbeat", 0, "heartbeat interval in seconds")
	flag.Parse()
}

func runStdinWatcher() {
	var buf [1]byte
	for {
		count, err := os.Stdin.Read(buf[:])
		if count > 0 {
			ch := buf[0]
			if ch == '\n' {
				log.Print("Got EOL. Exiting")
				break
			}
		}
		if err == io.EOF {
			log.Print("Got EOF. Exiting")
			break
		}
		if err != nil {
			log.Fatal(err)
		}
	}
	os.Exit(0)
}

func doBucketRequestFuller(bucket, baseURL string) (json []byte, err error) {
	terseBucketURL := baseURL + "pools/default/b/" + bucket
	req, err := http.NewRequest("GET", terseBucketURL, nil)
	if err != nil {
		return
	}

	err = cbauth.SetRequestAuth(req)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", userAgent)

	log.Printf("Sending request to %s. auth: %s", req.URL, req.Header.Get("Authorization"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}

	defer resp.Body.Close()

	log.Print("Got response ", resp)

	if resp.StatusCode != 200 {
		err = fmt.Errorf("Terse bucket info request failed: %v", resp)
		log.Print(err)
		return
	}

	return ioutil.ReadAll(resp.Body)
}

var bucketRequestClient = initBucketClient()

func initBucketClient() *http.Client {
	t := cbauth.WrapHTTPTransport(http.DefaultTransport, nil)
	rv := *http.DefaultClient
	rv.Transport = t
	return &rv
}

func doBucketRequestSimpler(bucket, baseURL string) (json []byte, err error) {
	terseBucketURL := baseURL + "pools/default/b/" + bucket
	resp, err := bucketRequestClient.Get(terseBucketURL)
	if err != nil {
		return
	}

	defer resp.Body.Close()

	log.Print("Got response ", resp)

	if resp.StatusCode != 200 {
		err = fmt.Errorf("Terse bucket info request failed: %v", resp)
		log.Print(err)
		return
	}

	return ioutil.ReadAll(resp.Body)
}

func performBucketRequest(bucket, baseURL string) (json []byte, err error) {
	if baseURL == "" {
		return nil, errors.New("Unconfigured url base")
	}
	if useFullerRequestFlag {
		return doBucketRequestFuller(bucket, baseURL)
	}
	return doBucketRequestSimpler(bucket, baseURL)
}

func getPathTail(req *http.Request) (bucket string) {
	path := req.RequestURI[1:]
	segments := strings.Split(path, "/")
	if len(segments) != 2 {
		return
	}
	bucket = segments[1]
	return
}

func authAndPerformBucketRequest(w http.ResponseWriter, req *http.Request, bucket, baseURL string) (err error) {
	var creds cbauth.Creds
	if externalFlag {
		creds, err = cbauth.GetExternalAuthenticator().AuthWebCreds(req)
	} else {
		creds, err = cbauth.AuthWebCreds(req)
	}

	if err == cbauth.ErrNoAuth {
		cbauth.SendUnauthorized(w)
		return nil
	}

	if err != nil {
		return
	}
	log.Printf("User name: `%s'", creds.Name())

	permission := "cluster.bucket[" + bucket + "].settings!read"

	canAccess, err := creds.IsAllowed(permission)
	if err != nil {
		log.Printf("Err: %v", err)
		return
	}
	if !canAccess {
		cbauth.SendForbidden(w, permission)
		return nil
	}

	if externalFlag {
		return
	}

	payload, err := performBucketRequest(bucket, baseURL)
	if err != nil {
		return
	}

	w.Write(payload)
	return
}

func doServeBucket(w http.ResponseWriter, req *http.Request) error {
	log.Printf("Serving: %s %s", req.Method, req.RequestURI)
	if req.Method != "GET" {
		http.NotFound(w, req)
		return nil
	}

	bucket := getPathTail(req)
	if bucket == "" {
		http.NotFound(w, req)
		return nil
	}
	return authAndPerformBucketRequest(w, req, bucket, mgmtURLFlag)
}

func doServeReconnect(w http.ResponseWriter, req *http.Request) error {
	hostport := getPathTail(req)
	if hostport == "" {
		http.NotFound(w, req)
		return nil
	}
	if !externalFlag {
		http.NotFound(w, req)
		return nil
	}

	err := initExternalTool(hostport)
	if err != nil {
		return err
	}

	uuid, err := cbauth.GetExternalAuthenticator().GetNodeUuid()
	if err != nil {
		return err
	}

	w.Write([]byte(uuid))
	return nil
}

func recogniseHostBucket(req *http.Request) (host, bucket string) {
	path := req.RequestURI[1:]
	segments := strings.Split(path, "/")
	if len(segments) != 3 {
		return
	}
	host = segments[1]
	bucket = segments[2]
	return
}

func doServeHostBucket(w http.ResponseWriter, req *http.Request) error {
	log.Printf("Serving: %s %s", req.Method, req.RequestURI)
	if req.Method != "GET" {
		http.NotFound(w, req)
		return nil
	}

	host, bucket := recogniseHostBucket(req)
	if bucket == "" || host == "" {
		http.NotFound(w, req)
		return nil
	}
	return authAndPerformBucketRequest(w, req, bucket, "http://"+host+"/")
}

var serveBucket = servingWithError(doServeBucket)
var serveHostBucket = servingWithError(doServeHostBucket)
var serveReconnect = servingWithError(doServeReconnect)

type errHandler func(w http.ResponseWriter, req *http.Request) error
type nonErrHandler func(w http.ResponseWriter, req *http.Request)

func servingWithError(body errHandler) nonErrHandler {
	return func(w http.ResponseWriter, req *http.Request) {
		err := body(w, req)
		if err != nil {
			http.Error(w, err.Error(), 500)
		}
	}
}

func initExternalTool(hostport string) error {
	return cbauth.InitExternalWithHeartbeat(
		toolName, hostport, authU, authP, heartbeat, heartbeat*2)
}

func maybeReinitCBAuth() {
	if authFlag == "" {
		return
	}
	up := strings.Split(authFlag, ":")
	authU, authP = up[0], up[1]
	u, err := url.Parse(mgmtURLFlag)
	if err != nil {
		log.Fatal("Failed to parse mgmtURLFlag: ", err)
	}
	if externalFlag {
		err = initExternalTool(u.Host)
	} else {
		_, err = cbauth.InternalRetryDefaultInit(u.Host, authU, authP)
	}
	if err != nil {
		log.Fatal("Failed to initialize cbauth: ", err)
	}
}

func main() {
	initFlags()
	if listenFlag == "" {
		fmt.Fprintln(os.Stderr, "Need both listen to be set!")
		flag.Usage()
		os.Exit(1)
	}
	if mgmtURLFlag != "" && !strings.HasSuffix(mgmtURLFlag, "/") {
		mgmtURLFlag += "/"
	}
	log.Printf("mgmtURL: %s", mgmtURLFlag)
	log.Printf("listen: %s", listenFlag)

	http.HandleFunc("/bucket/", serveBucket)
	http.HandleFunc("/h/", serveHostBucket)
	http.HandleFunc("/reconnect/", serveReconnect)
	go runStdinWatcher()
	maybeReinitCBAuth()
	log.Fatal(http.ListenAndServe(listenFlag, nil))
}
