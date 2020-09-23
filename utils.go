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

// ExtractCreds extracts Basic auth creds from request.
func ExtractCreds(req *http.Request) (user string, pwd string, err error) {
	auth := req.Header.Get("Authorization")
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

// ExtractOnBehalfIdentity extracts 'on behalf' identity from header.
func ExtractOnBehalfIdentity(req *http.Request) (user string,
	domain string, err error) {
	onBehalf := req.Header.Get("cb-on-behalf-of")
	if onBehalf == "" {
		return "", "", nil
	}
	return extractBase64Pair(onBehalf)
}
