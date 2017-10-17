// Package protected is used for creating "protected" connections
// that bypass Android's VpnService
package protected

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/getlantern/errors"
	"github.com/getlantern/golog"
	"github.com/getlantern/ops"
)

var (
	log              = golog.LoggerFor("lantern-android.protected")
	defaultDNSServer = "8.8.8.8"
	dnsPort          = 53
)

const (
	defaultDialTimeout = 1 * time.Minute
	readDeadline       = 15 * time.Second
	writeDeadline      = 15 * time.Second
	socketError        = -1
)

// Protect is the actual function to protect a connection. Same signature as
// https://developer.android.com/reference/android/net/VpnService.html#protect(java.net.Socket)
type Protect func(fileDescriptor int) error

type Protector struct {
	protect Protect
	dnsAddr syscall.Sockaddr
	dns     string
}

// New construct a protector from the protect function and DNS server IP address.
func New(protect Protect, dnsServerIP string) *Protector {
	ipAddr := net.ParseIP(dnsServerIP)
	if ipAddr == nil {
		log.Debugf("Invalid DNS server IP %s, default to %s", dnsServerIP, defaultDNSServer)
		dnsServerIP, ipAddr = defaultDNSServer, net.ParseIP(defaultDNSServer)
	}

	sockAddr := syscall.SockaddrInet4{Port: dnsPort}
	copy(sockAddr.Addr[:], ipAddr.To4())
	return &Protector{protect, &sockAddr, dnsServerIP}
}

// Resolve resolves the given address using a DNS lookup on a UDP socket
// protected by the given Protect function.
func (p *Protector) Resolve(network string, addr string) (*net.TCPAddr, error) {
	op := ops.Begin("protected-resolve").Set("addr", addr)
	defer op.End()
	conn, err := p.resolve(op, network, addr)
	return conn, op.FailIf(err)
}

func (p *Protector) resolve(op ops.Op, network string, addr string) (*net.TCPAddr, error) {
	host, port, err := splitHostPort(addr)
	if err != nil {
		return nil, err
	}

	// Check if we already have the IP address
	IPAddr := net.ParseIP(host)
	if IPAddr != nil {
		return &net.TCPAddr{IP: IPAddr, Port: port}, nil
	}

	// Create a datagram socket
	socketFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		err = errors.New("Error creating socket: %v", err)
		log.Error(err)
		return nil, err
	}
	defer syscall.Close(socketFd)

	// Here we protect the underlying socket from the
	// VPN connection by passing the file descriptor
	// back to Java for exclusion
	err = p.protect(socketFd)
	if err != nil {
		err = errors.New("Could not bind socket to system device: %v", err)
		log.Error(err)
		return nil, err
	}

	err = syscall.Connect(socketFd, p.dnsAddr)
	if err != nil {
		err = errors.New("Unable to call syscall.Connect: %v", err)
		log.Error(err)
		return nil, err
	}

	fd := uintptr(socketFd)
	file := os.NewFile(fd, "")
	defer file.Close()

	// return a copy of the network connection
	// represented by file
	fileConn, err := net.FileConn(file)
	if err != nil {
		log.Errorf("Error returning a copy of the network connection: %v", err)
		return nil, err
	}

	setQueryTimeouts(fileConn)

	log.Debugf("lookup %s via %s", host, p.dns)
	result, err := dnsLookup(host, fileConn)
	if err != nil {
		log.Errorf("Error doing DNS resolution: %v", err)
		return nil, err
	}
	ipAddr, err := result.PickRandomIP()
	if err != nil {
		log.Errorf("No IP address available: %v", err)
		return nil, err
	}
	return &net.TCPAddr{IP: ipAddr, Port: port}, nil
}

// Dial creates a new protected connection.
// - syscall API calls are used to create and bind to the
//   specified system device (this is primarily
//   used for Android VpnService routing functionality)
func (p *Protector) Dial(network, addr string, timeout time.Duration) (net.Conn, error) {
	ctx, _ := context.WithTimeout(context.Background(), timeout)
	return p.DialContext(ctx, network, addr)
}

// DialContext is same as Dial, but accepts a context instead of timeout value.
func (p *Protector) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	op := ops.Begin("protected-dial").Set("addr", addr)
	dl, ok := ctx.Deadline()
	if ok {
		op.Set("timeout", dl.Sub(time.Now()).Seconds())
	}
	defer op.End()

	// Dial in goroutine to support arbitrary cancellation.
	var conn net.Conn
	var err error
	chDone := make(chan bool)
	go func() {
		conn, err = p.dialContext(op, ctx, network, addr)
		if err != nil {
			log.Errorf("Could not dial %s %s: %v", network, addr, err)
		}
		select {
		case chDone <- true:
		default:
			if conn != nil {
				conn.Close()
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil, op.FailIf(ctx.Err())
	case <-chDone:
		return conn, op.FailIf(err)
	}
}

func (p *Protector) DialUDP(network string, laddr, raddr *net.UDPAddr) (net.Conn, error) {
	log.Debugf("Dialing udp addr %v", raddr)
	sockAddr := syscall.SockaddrInet4{Port: raddr.Port}
	copy(sockAddr.Addr[:], raddr.IP.To4())

	socketFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, errors.New("Could not create socket: %v", err)
	}
	conn := &protectedConn{sockAddr: &sockAddr, socketFd: socketFd}
	defer conn.cleanup()

	// Actually protect the underlying socket here
	err = p.protect(conn.socketFd)
	if err != nil {
		return nil, errors.New("Unable to protect socket to %v with fd %v and network %v: %v",
			raddr, conn.socketFd, network, err)
	}
	err = syscall.Connect(socketFd, &sockAddr)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	// finally, convert the socket fd to a net.Conn
	err = conn.convert()
	if err != nil {
		return nil, errors.New("Error converting protected connection: %v", err)
	}
	return conn.Conn, nil
}

// dialContext checks if context has been done between each phase to avoid
// unnecessary work, but doesn't support arbitrary cancellation.
func (p *Protector) dialContext(op ops.Op, ctx context.Context, network, addr string) (net.Conn, error) {
	var socketType int
	switch network {
	case "tcp", "tcp4", "tcp6":
		socketType = syscall.SOCK_STREAM
	case "udp", "udp4", "udp6":
		socketType = syscall.SOCK_DGRAM
	default:
		err := errors.New("Unsupported network: %v", network)
		log.Error(err)
		return nil, err
	}

	log.Debugf("protected dialing %s %s", network, addr)

	// Try to resolve it
	tcpAddr, err := p.Resolve(network, addr)
	if err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// continue
	}

	sockAddr := syscall.SockaddrInet4{Port: tcpAddr.Port}
	copy(sockAddr.Addr[:], tcpAddr.IP.To4())
	socketFd, err := syscall.Socket(syscall.AF_INET, socketType, 0)
	if err != nil {
		return nil, errors.New("Could not create socket: %v", err)
	}
	conn := &protectedConn{sockAddr: &sockAddr, socketFd: socketFd}
	defer conn.cleanup()

	// Actually protect the underlying socket here
	err = p.protect(conn.socketFd)
	if err != nil {
		return nil, errors.New("Unable to protect socket to %v with fd %v and network %v: %v",
			addr, conn.socketFd, network, err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// continue
	}

	// Actually connect the underlying socket
	err = conn.connectSocket(ctx)
	if err != nil {
		return nil, errors.New("Unable to connect socket to %v: %v", addr, err)
	}

	// finally, convert the socket fd to a net.Conn
	err = conn.convert()
	if err != nil {
		return nil, errors.New("Error converting protected connection: %v", err)
	}
	return conn.Conn, nil
}

type protectedConn struct {
	net.Conn
	mutex    sync.Mutex
	isClosed bool
	socketFd int
	sockAddr syscall.Sockaddr
}

// connectSocket makes the connection to the given IP address port
// for the given socket fd
func (conn *protectedConn) connectSocket(ctx context.Context) error {
	errCh := make(chan error)
	go func() {
		errCh <- syscall.Connect(conn.socketFd, conn.sockAddr)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// converts the protected connection specified by
// socket fd to a net.Conn
func (conn *protectedConn) convert() error {
	conn.mutex.Lock()
	file := os.NewFile(uintptr(conn.socketFd), "")
	// dup the fd and return a copy
	fileConn, err := net.FileConn(file)
	// closes the original fd
	file.Close()
	conn.socketFd = socketError
	if err != nil {
		conn.mutex.Unlock()
		return err
	}
	conn.Conn = fileConn
	conn.mutex.Unlock()
	return nil
}

// cleanup is run whenever we encounter a socket error
// we use a mutex since this connection is active in a variety
// of goroutines and to prevent any possible race conditions
func (conn *protectedConn) cleanup() {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if conn.socketFd != socketError {
		syscall.Close(conn.socketFd)
		conn.socketFd = socketError
	}
}

// Close is used to destroy a protected connection
func (conn *protectedConn) Close() (err error) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if !conn.isClosed {
		conn.isClosed = true
		if conn.Conn == nil {
			if conn.socketFd == socketError {
				err = nil
			} else {
				err = syscall.Close(conn.socketFd)
				// update socket fd to socketError
				// to make it explicit this connection
				// has been closed
				conn.socketFd = socketError
			}
		} else {
			err = conn.Conn.Close()
		}
	}
	return err
}

// configure DNS query expiration
func setQueryTimeouts(c net.Conn) {
	now := time.Now()
	c.SetReadDeadline(now.Add(readDeadline))
	c.SetWriteDeadline(now.Add(writeDeadline))
}

// splitHostAndPort is a wrapper around net.SplitHostPort that also uses strconv
// to convert the port to an int
func splitHostPort(addr string) (string, int, error) {
	host, sPort, err := net.SplitHostPort(addr)
	if err != nil {
		log.Errorf("Could not split network address: %v", err)
		return "", 0, errors.Wrap(err)
	}
	port, err := strconv.Atoi(sPort)
	if err != nil {
		log.Errorf("No port number found %v", err)
		return "", 0, errors.Wrap(err)
	}
	return host, port, nil
}
