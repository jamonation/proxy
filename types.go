package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"

	"github.com/satori/uuid"
)

const httpProxy serverType = "httpProxy"
const tlsProxy serverType = "tlsProxy"

// Listener gives a Listen() method and ACLs to anything that wants it
type Listener interface {
	Listen(string) error
	GetType() serverType
}

// HTTPProxy implements Listener
type HTTPProxy struct {
	Server           http.Server
	Wg               *sync.WaitGroup
	acls             allowMap
	ctx              context.Context
	upstreamTLSProxy string // used for CONNECT tunnels
}

// TLSProxy implements Listener
type TLSProxy struct {
	Conn    net.Conn
	TLSConn *tls.Conn
	Wg      *sync.WaitGroup
	ctx     context.Context
}

type requestID struct {
	uuid.UUID
}

type allowMap map[string][]aclEntry      // {"hosts": [{"google.com": {"cache": true}}], "urls": [{"google.com": {"cache": true}}]}
type aclEntry map[string]map[string]bool // {"https:\/\/www\.google\.com\/test": {"cache": true}}

type serverType string
