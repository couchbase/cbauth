package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/couchbase/cbauth"
	couchbase "github.com/couchbaselabs/go-couchbase"
)

var serverURL = flag.String("serverURL", "http://localhost:9000", "couchbase server URL")
var poolName = flag.String("poolName", "default", "pool name")
var bucketName = flag.String("bucketName", "default", "bucket name")

var keyToSet = flag.String("keyToSet", "foo", "key to Set")
var valueToSet = flag.String("valueToSet", "bar", "value to Set")

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nNOTE: that this program requires correctly set cbauth env variable.")
		fmt.Fprintf(os.Stderr, "E.g: CBAUTH_REVRPC_URL='http://Administrator:asdasd@127.0.0.1:9000/cbauth-demo' \\\n"+
			"%s --serverURL=http://10.17.3.172:9000 --bucketName=bucket-foo\n\n", os.Args[0])
	}
	flag.Parse()

	// this will give go-couchbase unlimited access to all http
	// endpoints it has access to.
	//
	// NOTE: it's kinda hackish. And note that it _will override_
	// whatever auth is given at client instantiation. In this
	// program there is _no auth_ that is given anywhere as auth
	// is supposed to come from cbauth.
	transport := cbauth.WrapHTTPTransport(couchbase.HTTPTransport, nil)
	couchbase.HTTPClient.Transport = transport

	client, err := couchbase.ConnectWithAuth(*serverURL, cbauth.NewAuthHandler(nil))
	if err != nil {
		log.Fatal(err)
	}

	p, err := client.GetPool("default")
	if err != nil {
		log.Fatal(err)
	}

	b, err := p.GetBucket(*bucketName)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Setting key `%s' to `%s' in bucket `%s'", *keyToSet, *valueToSet, *bucketName)
	err = b.SetRaw(*keyToSet, 0, []byte(*valueToSet))
	if err != nil {
		log.Fatal(err)
	}
}
