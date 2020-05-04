package proxyProtocol

import (
	"net"
	"time"
)

// TCPProxyListener is used to wrap an underlying listener,
// whose connections may be using the HAProxy Proxy Protocol (version 1).
// If the connection is using the protocol, the RealAddr() will return
// the correct client address.
//
// Optionally define ProxyHeaderTimeout to set a maximum time to
// receive the Proxy Protocol Header. Zero means no timeout.
type TCPProxyListener struct {
	Listener           *net.TCPListener
	ProxyHeaderTimeout time.Duration
}

// Accept waits for and returns the next connection to the listener.
func (p *TCPProxyListener) Accept() (net.Conn, error) {
	// Get the underlying connection
	conn, err := p.Listener.Accept()
	if err != nil {
		return nil, err
	}
	newConn := NewTCPConn(conn, p.ProxyHeaderTimeout)
	// newConn.bufReader = bufio.NewReader(conn)
	return newConn, nil
}

// Close closes the underlying listener.
func (p *TCPProxyListener) Close() error {
	return p.Listener.Close()
}

// Addr returns the underlying listener's network address.
func (p *TCPProxyListener) Addr() net.Addr {
	return p.Listener.Addr()
}

// TODO: UDP
