package main

import (
	"flag"
	"log"
	"proxy"
	"sync"
)

var (
	httpListenAddr string
	tlsListenAddr  string
)

func init() {
	flag.StringVar(&httpListenAddr, "httpListenAddr", "127.0.0.1:38000", "Address to listen on for HTTP_PROXY connections")
	flag.StringVar(&tlsListenAddr, "tlsListenAddr", "127.0.0.1:38443", "Address to listen on for internal CONNECT proxy connections")
	flag.Parse()
}

func main() {

	wg := sync.WaitGroup{}
	wg.Add(2)

	httpProxy := proxy.NewHTTPProxy(&wg, tlsListenAddr)
	tlsProxy := proxy.NewTLSProxy(&wg)

	go runServer(httpProxy, httpListenAddr)
	go runServer(tlsProxy, tlsListenAddr)

	wg.Wait()
}

func runServer(l proxy.Listener, addr string) {
	log.Printf("%s listening on %s\n", l.GetType(), addr)
	l.Listen(addr)
}
