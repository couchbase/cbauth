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
