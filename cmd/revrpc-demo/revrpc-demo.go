package main

import (
	"log"
	"net/rpc"
	"os"
	"time"

	"github.com/couchbase/cbauth/revrpc"
)

// HelloMsg is example request type.
type HelloMsg struct {
	Name  string
	Sleep time.Duration
}

// HelloResponseMsg is example response type.
type HelloResponseMsg struct {
	Msg string
}

// RPC is our example rpc instance.
type RPC struct{}

// Hello is example revrpc exported method.
func (r RPC) Hello(req *HelloMsg, res *HelloResponseMsg) error {
	log.Printf("Got hello from %s", req.Name)
	*res = HelloResponseMsg{Msg: "Hello, " + req.Name}
	time.Sleep(100*time.Millisecond + req.Sleep)
	log.Printf("Responded to %s", req.Name)
	return nil
}

func rpcSetup(rs *rpc.Server) error {
	log.Print("Ready!")
	rs.Register(RPC{})
	return nil
}

func maybeSetEnv(key, value string) {
	if os.Getenv(key) != "" {
		return
	}
	os.Setenv(key, value)
}

func main() {
	maybeSetEnv("NS_SERVER_CBAUTH_RPC_URL", "http://127.0.0.1:9000/rpcdemo")
	maybeSetEnv("NS_SERVER_CBAUTH_USER", "Administrator")
	maybeSetEnv("NS_SERVER_CBAUTH_PWD", "asdasd")
	log.Fatal(revrpc.BabysitService(rpcSetup, nil, nil))
}
