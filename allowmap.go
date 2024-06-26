package proxy

import (
	"log"
	"net/http"
)

func (m allowMap) check(r *http.Request) bool {
	switch {
	case m.checkHost(r):
		log.Printf("Allowing host %v\n", r.URL.Hostname())
		return true
	case m.checkURL(r):
		log.Printf("Allowing url %v\n", r.URL.String())
		return true
	default:
		log.Printf("Blocking %v\n", r.URL.String())
		return false
	}
}

func (m allowMap) checkHost(r *http.Request) (ok bool) {
	// redo this to lookup in a map of compiled regexps
	for _, acl := range m["hosts"] {
		if _, ok := acl[r.URL.Hostname()]; ok {
			return ok
		}
	}
	return false
}

func (m allowMap) checkURL(r *http.Request) (ok bool) {
	// implement by using a lookup in a map of compiled regexps
	return false
}
