package cbauth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/couchbase/cbauth/httpreq"
)

// SplitHostPort separates hostport into string host and numeric port.
func SplitHostPort(hostport string) (host string, port int, err error) {
	host, portS, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, err
	}
	port64, err := strconv.ParseUint(portS, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("port of `%s' is expected to be numeric but isn't: %v", hostport, err)
	}
	port = int(port64)
	return
}

func extractBase64Pair(s string) (user, extra string, err error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return
	}
	idx := bytes.IndexByte(decoded, ':')
	if idx < 0 {
		err = errors.New("Malformed header")
		return
	}
	user = string(decoded[0:idx])
	extra = string(decoded[(idx + 1):])
	return
}

func ExtractCredsGeneric(hdr httpreq.HttpHeader) (user string, pwd string, err error) {
	auth := hdr.Get("Authorization")
	if auth == "" {
		return "", "", nil
	}

	basicPrefix := "Basic "
	if !strings.HasPrefix(auth, basicPrefix) {
		err = errors.New("Non-basic auth is not supported")
		return
	}
	return extractBase64Pair(auth[len(basicPrefix):])
}

// TODO: Remove this when query moves to using httpreq alone
func ExtractCreds(req *http.Request) (user string, pwd string, err error) {
	return ExtractCredsGeneric(req.Header)
}

// TODO: Remove this when query moves to using httpreq alone
func ExtractOnBehalfIdentity(req *http.Request) (user string,
	domain string, err error) {
	return ExtractOnBehalfIdentityGeneric(req.Header)
}

// ExtractOnBehalfIdentityGeneric extracts 'on behalf' identity from header.
func ExtractOnBehalfIdentityGeneric(hdr httpreq.HttpHeader) (user string,
	domain string, err error) {
	onBehalf := hdr.Get("cb-on-behalf-of")
	if onBehalf == "" {
		return "", "", nil
	}
	return extractBase64Pair(onBehalf)
}
