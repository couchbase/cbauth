package main

import (
	"flag"
	"log"
	"os"

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
		log.Print("Non --try mode is not implemented yet")
		os.Exit(1)
	}

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
