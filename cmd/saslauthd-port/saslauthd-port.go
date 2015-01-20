package main

import (
	"flag"
	"io"
	"log"
	"net/rpc"
	"os"

	"github.com/couchbase/cbauth/revrpc"
	"github.com/couchbase/cbauth/saslauthd"
)

var (
	name    string
	pwd     string
	service string
	realm   string
	tryAuth bool
	tryMany int
)

// SASLDAuth is type exported via rpc.
type SASLDAuth struct{}

// AuthReq is struct used by request of SASLDAuth.Check
type AuthReq struct {
	User string
	Pwd  string
}

// Check method verifies given creds.
func (sa SASLDAuth) Check(req *AuthReq, ok *bool) (err error) {
	*ok, err = saslauthd.Auth(req.User, req.Pwd, service, realm)
	return
}

func setupPortRPC(rs *rpc.Server) error {
	rs.Register(SASLDAuth{})
	return nil
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

func doRunPort() error {
	svc, err := revrpc.GetDefaultServiceFromEnv("saslauthd-port")
	if err != nil {
		return err
	}
	go runStdinWatcher()
	return revrpc.BabysitService(setupPortRPC, svc, nil)
}

func main() {
	flag.StringVar(&name, "user", "", "username to --try auth for")
	flag.StringVar(&pwd, "pwd", "", "password to --try auth for")
	flag.StringVar(&service, "service", "couchbase", "service name to use")
	flag.StringVar(&realm, "realm", "", "realm name to use")
	flag.BoolVar(&tryAuth, "try", false, "try auth under given --user and --pwd and exit")
	flag.IntVar(&tryMany, "try-many", 0, "repeat --try multiple times")

	flag.Parse()

	if tryMany > 0 {
		tryAuth = true
	}

	if tryAuth && (name == "" || pwd == "") {
		log.Print("Need --user and --password when --try is given")
		flag.Usage()
		os.Exit(1)
	}

	if !tryAuth {
		log.Fatal(doRunPort())
	} else {
		doRunTry()
	}
}

func doRunTry() {
	if tryMany > 0 {
		runTryMany(tryMany)
	} else {
		ok, err := saslauthd.Auth(name, pwd, service, realm)
		if err != nil {
			log.Fatal(err)
		}
		printResult(ok)
	}
}

func printResult(ok bool) {
	if ok {
		log.Print("Success!!!")
	} else {
		log.Print("Failure")
	}
}

func runTryMany(count int) {
	readys := make(chan bool, count)
	for i := 0; i < count; i++ {
		go func() {
			var err error
			var ok bool
			ok, err = saslauthd.Auth(name, pwd, service, realm)
			if err != nil {
				log.Fatal(err)
			}
			readys <- ok
		}()
	}
	ok := true
	for i := 0; i < count; i++ {
		ok = ok && <-readys
	}
	printResult(ok)
}
