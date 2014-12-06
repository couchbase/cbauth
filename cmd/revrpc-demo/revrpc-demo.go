package main

import (
	"log"
	"net/rpc"
	"os"
	"time"

	"github.com/couchbase/cbauth/revrpc"
)

type HelloMsg struct {
	Name  string
	Sleep time.Duration
}

type HelloResponseMsg struct {
	Msg string
}

type RPC struct{}

func (_ RPC) Hello(req *HelloMsg, res *HelloResponseMsg) error {
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

func MaybeSetEnv(key, value string) {
	if os.Getenv(key) != "" {
		return
	}
	os.Setenv(key, value)
}

func main() {
	MaybeSetEnv("NS_SERVER_CBAUTH_RPC_URL", "http://127.0.0.1:9000/rpcdemo")
	MaybeSetEnv("NS_SERVER_CBAUTH_USER", "Administrator")
	MaybeSetEnv("NS_SERVER_CBAUTH_PWD", "asdasd")
	log.Fatal(revrpc.BabysitService(rpcSetup, nil, nil))
}
