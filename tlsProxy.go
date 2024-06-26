package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"
)

// NewTLSProxy returns a TLSProxy that implements a Listener
func NewTLSProxy(wg *sync.WaitGroup) Listener {
	return &TLSProxy{
		Conn: nil,
		Wg:   wg,
		ctx:  nil,
	}
}

var certMap certs = make(certs)
var certMapLock sync.Mutex = sync.Mutex{}

type certs map[string]certificate

type certificate struct {
	Pubkey  *bytes.Buffer
	PrivKey *bytes.Buffer
}

func NewTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(hInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// running in a goroutine, so need the mutex to protect the map from racing requests
			certMapLock.Lock()
			defer certMapLock.Unlock()

			var certPEM, certPrivKeyPEM *bytes.Buffer
			var cert certificate
			var ok bool
			if cert, ok = certMap[hInfo.ServerName]; ok == false {
				fmt.Printf("creating cert for %v\n", hInfo.ServerName)
				certPEM, certPrivKeyPEM = makeCert(hInfo.ServerName)
				cert = certificate{
					Pubkey:  certPEM,
					PrivKey: certPrivKeyPEM,
				}
				certMap[hInfo.ServerName] = cert
			} else {
				fmt.Printf("reusing cert for %v\n", hInfo.ServerName)
			}
			serverCert, err := tls.X509KeyPair(cert.Pubkey.Bytes(), cert.PrivKey.Bytes())
			if err != nil {
				return nil, err
			}
			return &serverCert, nil
		},
	}
}

// Listen waits for incoming connects for anything using HTTPS_PROXY
// It generates certificates and signs them on demand using the Academy CA key pair
func (s *TLSProxy) Listen(laddr string) error {
	listener, err := tls.Listen("tcp", laddr, NewTLSConfig())
	if err != nil {
		return err

	}

	var wg sync.WaitGroup

	for {
		s.Conn, err = listener.Accept()
		if err != nil {
			log.Printf("server: accept: %s", err)
			break
		}

		wg.Add(1)
		go s.handleTLSConn(&wg)
		wg.Wait()
	}

	return nil
}

func (s *TLSProxy) handleTLSConn(wg *sync.WaitGroup) {
	defer s.Conn.Close()
	defer wg.Done()

	var ok bool
	s.TLSConn, ok = s.Conn.(*tls.Conn)
	if !ok {
		fmt.Printf("error establishing connection to %v\n", s.Conn.RemoteAddr().String())
		return
	}
	defer s.TLSConn.Close()

	// docs say low level connection manipulation needs these
	s.TLSConn.SetDeadline(time.Now().Add(5 * time.Second))
	err := s.TLSConn.Handshake()
	if err != nil {
		fmt.Printf("tls handshake error: %v\n", err)
		return
	}

	req, err := createReq(s.TLSConn)
	if err != nil {
		fmt.Printf("Closed TLS conn? %v, %s\n", s.TLSConn.ConnectionState(), err)
		return
	}

	log.Printf("Intercepting CONNECT request to: %#v for %v\n", req.URL, req.Header.Get("X-Forwarded-For"))
	var h string
	if req.Method != http.MethodPost || req.URL.RawQuery != "" {
		h = hash(fmt.Sprintf("%v+%v", req.Method, req.URL.String()))
	}

	b := []byte{}
	cacheResponse := true
	switch isCached(h) {
	case true:
		b, err = fromCache(h)
		if err != nil {
			fmt.Printf("%s", err)
		}
	case false:
		b, cacheResponse, err = fromRequest(req)
		if err != nil {
			fmt.Printf("%s", err)
		}
		if req.Method != http.MethodPost && cacheResponse {
			err := writeCache(h, b)
			if err != nil {
				fmt.Printf("%s", err)
			}
		}
	}
	if err != nil {
		fmt.Printf("%s", err)
	}

	// this could be a multiwriter with the cache file some day
	log.Printf("Writing response for %v\n", req.URL.String())
	s.TLSConn.Write(b)
	log.Printf("Done writing response for %v\n", req.URL.String())

}

func createReq(conn *tls.Conn) (*http.Request, error) {
	reader := bufio.NewReader(conn)

	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, fmt.Errorf("error reading request: %v\n", err)
	}

	req.URL.Scheme = "https"
	req.URL.Host = req.Host
	req.RequestURI = "" // unset for client requests

	log.Printf("Read request for %v\n", req.URL.String())
	return req, nil
}

func fromRequest(req *http.Request) ([]byte, bool, error) {
	var cacheResponse bool = true

	client := http.Client{
		Transport: &http.Transport{
			TLSNextProto: map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, cacheResponse, fmt.Errorf("error making request: %v\n", err)
	}
	defer resp.Body.Close()

	cacheHeader := resp.Header.Get("Cache-Control")
	if strings.Contains(cacheHeader, "no-cache") {
		cacheResponse = false
	}

	b, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return nil, cacheResponse, fmt.Errorf("error dumping response: %v\n", err)
	}
	return b, cacheResponse, nil
}

func (s *TLSProxy) GetType() serverType {
	return tlsProxy
}
