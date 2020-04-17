package proxyProtocol

import (
	"bufio"
	"io"
	"net"
	"sync"
	"time"
)

// Listener is used to wrap an underlying listener,
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

// Conn is used to wrap and underlying connection which
// may be speaking the Proxy Protocol. If it is, the RemoteAddr() will
// return the address of the client instead of the proxy address.
type TCPConn struct {
	bufReader          *bufio.Reader
	conn               net.Conn
	dstAddr            *net.TCPAddr
	srcAddr            *net.TCPAddr
	proxyDataAvailable bool
	once               sync.Once
	proxyHeaderTimeout time.Duration
}

// Accept waits for and returns the next connection to the listener.
func (p *TCPProxyListener) Accept() (net.Conn, error) {
	// Get the underlying connection
	conn, err := p.Listener.Accept()
	if err != nil {
		return nil, err
	}
	newConn := NewTCPConn(conn, p.ProxyHeaderTimeout)
	newConn.bufReader = bufio.NewReader(conn)
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

// NewConn is used to wrap a net.Conn that may be speaking
// the proxy protocol into a proxyproto.Conn
func NewTCPConn(conn net.Conn, timeout time.Duration) *TCPConn {
	pConn := &TCPConn{
		bufReader:          bufio.NewReader(conn),
		conn:               conn,
		proxyHeaderTimeout: timeout,
	}
	return pConn
}

// Read is check for the proxy protocol header when doing
// the initial scan. If there is an error parsing the header,
// it is returned and the socket is closed.
func (p *TCPConn) Read(b []byte) (int, error) {
	// var err error
	// p.once.Do(func() { err = p.ProxyHandshake() })
	// if err != nil {
	// 	return 0, err
	// }
	return p.bufReader.Read(b)
}

func (p *TCPConn) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := p.conn.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(p.conn, r)
}

func (p *TCPConn) WriteTo(w io.Writer) (int64, error) {
	// var err error
	// p.once.Do(func() { err = p.ProxyHandshake() })
	// if err != nil {
	// 	return 0, err
	// }
	return p.bufReader.WriteTo(w)
}

func (p *TCPConn) Write(b []byte) (int, error) {
	return p.conn.Write(b)
}

func (p *TCPConn) Close() error {
	return p.conn.Close()
}

func (p *TCPConn) LocalAddr() net.Addr {
	return p.conn.LocalAddr()
}

func (p *TCPConn) RealLocalAddr() net.Addr {
	if p.proxyDataAvailable {
		return p.dstAddr
	} else {
		return p.conn.LocalAddr()
	}
}

// RemoteAddr returns the address of the client if the proxy
// protocol is being used, otherwise just returns the address of
// the socket peer. If there is an error parsing the header, the
// address of the client is not returned, and the socket is closed.
// Once implication of this is that the call could block if the
// client is slow. Using a Deadline is recommended if this is called
// before Read()
func (p *TCPConn) RemoteAddr() net.Addr {
	return p.conn.RemoteAddr()
}

func (p *TCPConn) RealRemoteAddr() net.Addr {
	if p.proxyDataAvailable {
		return p.srcAddr
	} else {
		return p.conn.RemoteAddr()
	}
}

func (p *TCPConn) IsProxyDataAvailable() bool {
	return p.proxyDataAvailable
}

func (p *TCPConn) SetDeadline(t time.Time) error {
	return p.conn.SetDeadline(t)
}

func (p *TCPConn) SetReadDeadline(t time.Time) error {
	return p.conn.SetReadDeadline(t)
}

func (p *TCPConn) SetWriteDeadline(t time.Time) error {
	return p.conn.SetWriteDeadline(t)
}

func (p *TCPConn) ProxyHandshake() error {
	if p.proxyHeaderTimeout != 0 {
		readDeadLine := time.Now().Add(p.proxyHeaderTimeout)
		p.conn.SetReadDeadline(readDeadLine)
		defer p.conn.SetReadDeadline(time.Time{})
	}

	line, err := ConsumeProxyLine(p.bufReader)
	if err != nil {
		return err
	}
	if line == nil {
		return nil
	}

	p.srcAddr = line.SrcAddr.(*net.TCPAddr)
	p.dstAddr = line.DstAddr.(*net.TCPAddr)
	p.proxyDataAvailable = true
	return nil
}

// TODO: UDP
