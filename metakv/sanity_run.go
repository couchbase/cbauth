package metakv

import (
	"log"
	"os"
)

func init() {
	if os.Getenv("COUCHBASE_METAKV_SANITY") != "" {
		ExecuteBasicSanityTest(log.Print)
	}

	if l := os.Getenv("COUCHBASE_METAKV_DEBUG"); l != "" {
		log.Printf("Starting _metakv debugging endpoint on `%s'", l)
		GoRunDebugEndpoint(l)
	}
}
