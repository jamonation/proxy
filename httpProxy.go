package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// NewHTTPProxy returns an HTTPProxy that implements a Listener
func NewHTTPProxy(wg *sync.WaitGroup, upstreamTLSProxy string) Listener {
	return &HTTPProxy{
		Server:           http.Server{},
		Wg:               wg,
		acls:             map[string][]aclEntry{},
		upstreamTLSProxy: upstreamTLSProxy,
	}
}

// Listen waits for incoming connects for anything using HTTP_PROXY
func (s *HTTPProxy) Listen(addr string) error {
	s.Server = http.Server{
		Addr:    addr,
		Handler: http.HandlerFunc(s.proxyRequest),
	}

	if err := s.loadAcls(); err != nil {
		return err
	}

	if err := s.Server.ListenAndServe(); err != nil {
		return err
	}

	return nil
}

func (s *HTTPProxy) proxyRequest(w http.ResponseWriter, req *http.Request) {
	var err error
	var resp *http.Response

	// if !s.acls.check(req) {
	// 	w.WriteHeader(http.StatusForbidden)
	// 	return
	// }

	switch req.Method {
	case "CONNECT":
		s.handleConnect(w, req)
		return
	case "GET":
		log.Printf("GET %v\n", req.RequestURI)
		resp, err = http.Get(req.RequestURI)
	case "HEAD":
		log.Printf("HEAD %v\n", req.RequestURI)
		resp, err = http.Head(req.RequestURI)
	default:
		w.WriteHeader(http.StatusNotImplemented)
		fmt.Fprintln(w, "Only GET, HEAD, and CONNECT are supported at the moment")
		return
	}

	if err != nil {
		msg := fmt.Sprintf("error requesting %v", req.RequestURI)
		http.Error(w, msg, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	writer := io.Writer(w)
	_, err = io.Copy(writer, resp.Body)
	if err != nil {
		http.Error(w, "error parsing request", http.StatusInternalServerError)
		return
	}

}

func (s *HTTPProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	dstConn, err := net.DialTimeout("tcp", s.upstreamTLSProxy, 5*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	srcConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	go transfer(dstConn, srcConn)
	go transfer(srcConn, dstConn)

}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

// LoadAcls loads access controls
func (s *HTTPProxy) loadAcls() error {
	log.Printf("Loading ACLs\n")
	f, err := os.ReadFile("allowmap.json")
	if err != nil {
		return err
	}

	err = json.Unmarshal(f, &s.acls)
	if err != nil {
		return err
	}
	log.Printf("Loaded %d hostname ACLs, %d URL ACLs\n", len(s.acls["hosts"]), len(s.acls["urls"]))

	return nil
}

func (s *HTTPProxy) GetType() serverType {
	return httpProxy
}
