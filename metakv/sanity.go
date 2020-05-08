package metakv

import (
	"fmt"
)

func noPanic(err error) {
	if err != nil {
		panic(err)
	}
}

func doAppend(s *store, path string, value string, sensitive bool) error {
	oldv, rev, err := s.get(path)
	if err != nil {
		return err
	}
	if rev == nil {
		rev = RevCreate
	}
	oldv = append(oldv, []byte(value)...)
	return s.set(path, oldv, rev, sensitive)
}

func kvEqual(e kvEntry, key string, val []byte, sensitive bool) bool {
	if e.Value == nil && val != nil || e.Value != nil && val == nil {
		return false
	}
	// deletions signal rev that is interface{}([]byte(nil))
	if val == nil && len(e.Rev) != 0 {
		return false
	}
	return e.Path == key && string(e.Value) == string(val) &&
		e.Sensitive == sensitive
}

func assertKV(log func(v ...interface{}), e kvEntry, key string, val []byte,
	sensitive bool) {
	if !kvEqual(e, key, val, sensitive) {
		log(fmt.Sprintf("bad mutation: %v", e))
		panic("bad mutation")
	}
}

func assertAndDelete(s *store, key string, val string) {
	v, r, err := s.get(key)
	noPanic(err)
	if r == nil || string(v) != val {
		panic(fmt.Sprintf("wrong value: %v", string(v)))
	}

	err = s.delete(key, r)
	noPanic(err)
}

// ExecuteBasicSanityTest runs basic sanity test.
func ExecuteBasicSanityTest(log func(v ...interface{})) {
	doExecuteBasicSanityTest(log, defaultStore)
}

func doExecuteBasicSanityTest(log func(v ...interface{}), s *store) {
	log("Starting basic sanity test")
	l, err := s.listAllChildren("/_sanity/")
	noPanic(err)
	for _, kve := range l {
		err := s.delete(kve.Path, nil)
		noPanic(err)
	}
	log("cleaned up /_sanity/ subspace")

	v, r, err := s.get("/_sanity/nonexistant")
	noPanic(err)
	if v != nil || r != nil {
		panic("badness")
	}

	buf := make(chan kvEntry, 128)
	cancelChan := make(chan struct{})

	defer func() {
		if cancelChan != nil {
			close(cancelChan)
		}
	}()

	go func() {
		err := s.runObserveChildren("/_sanity/", func(e kvEntry) error {
			buf <- e
			return nil
		}, cancelChan)
		log("Sanity observe loop exited")
		close(buf)
		if err != nil {
			panic(err)
		}
	}()

	err = doAppend(s, "/_sanity/key", "value", false)
	noPanic(err)

	v, r, err = s.get("/_sanity/key")
	noPanic(err)
	if r == nil || string(v) != "value" {
		panic("badness")
	}

	err = s.set("/_sanity/key", []byte("new value"), r, false)
	noPanic(err)

	err = doAppend(s, "/_sanity/secret", "secret", true)
	noPanic(err)

	err = s.delete("/_sanity/key", r)
	if err != ErrRevMismatch {
		panic("must have ErrRevMismatch")
	}

	assertAndDelete(s, "/_sanity/secret", "secret")
	assertAndDelete(s, "/_sanity/key", "new value")

	l, err = s.listAllChildren("/_sanity/")
	noPanic(err)
	if len(l) != 0 {
		panic("len is bad")
	}

	close(cancelChan)
	cancelChan = nil

	var allMutations []kvEntry
	for kve := range buf {
		allMutations = append(allMutations, kve)
	}

	if len(allMutations) != 5 {
		panic(fmt.Sprintf("bad mutations size: %d (%v)",
			len(allMutations), allMutations))
	}

	assertKV(log, allMutations[0], "/_sanity/key", []byte("value"), false)
	assertKV(log, allMutations[1], "/_sanity/key", []byte("new value"),
		false)
	assertKV(log, allMutations[2], "/_sanity/secret", []byte("secret"),
		true)
	assertKV(log, allMutations[3], "/_sanity/secret", nil, false)
	assertKV(log, allMutations[4], "/_sanity/key", nil, false)

	err = s.set("/_sanity/key", []byte("more value"), nil, false)
	noPanic(err)
	v, r, err = s.get("/_sanity/key")
	noPanic(err)
	if r == nil || string(v) != "more value" {
		panic("expecting more value got: " + string(v))
	}
	err = s.delete("/_sanity/key", nil)
	noPanic(err)
	_, r, err = s.get("/_sanity/key")
	noPanic(err)
	if r != nil {
		panic("expected key to be missing after successful delete")
	}

	log("Completed metakv sanity test")
}
