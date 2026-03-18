module github.com/couchbase/cbauth

go 1.24.0

require (
	github.com/couchbase/clog v0.1.0
	github.com/couchbase/go-couchbase v0.1.1
	github.com/couchbase/gomemcached v0.3.3
)

require (
	github.com/couchbase/goutils v0.3.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	golang.org/x/crypto v0.46.0 // indirect
)

replace github.com/couchbase/gomemcached => github.com/couchbase/gomemcached v0.2.1
