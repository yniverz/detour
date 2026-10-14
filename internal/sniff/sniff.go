// Package sniff provides a listener that serves TLS and plain-text connections
// on the same port, deciding per connection from its first byte.
package sniff

import (
	"bufio"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"
)

// tlsHandshakeRecord is the first byte of every TLS connection (ContentType handshake).
const tlsHandshakeRecord = 0x16

// Listener wraps a net.Listener. Accept returns *tls.Conn for TLS clients and a
// plain net.Conn for everything else. Sniffing happens in a goroutine per
// connection, so a silent client cannot block other connections.
type Listener struct {
	inner   net.Listener
	tlsConf *tls.Config
	timeout time.Duration

	conns     chan net.Conn
	errs      chan error
	done      chan struct{}
	closeOnce sync.Once
}

// New starts accepting on inner. timeout bounds how long a client may take to
// send its first byte (0 = no limit).
func New(inner net.Listener, tlsConf *tls.Config, timeout time.Duration) *Listener {
	l := &Listener{
		inner:   inner,
		tlsConf: tlsConf,
		timeout: timeout,
		conns:   make(chan net.Conn),
		errs:    make(chan error, 1),
		done:    make(chan struct{}),
	}
	go l.acceptLoop()
	return l
}

func (l *Listener) acceptLoop() {
	var delay time.Duration
	for {
		c, err := l.inner.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				// Temporary resource exhaustion: back off like net/http does.
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else if delay *= 2; delay > time.Second {
					delay = time.Second
				}
				select {
				case <-time.After(delay):
					continue
				case <-l.done:
					return
				}
			}
			select {
			case l.errs <- err:
			case <-l.done:
			}
			return
		}
		delay = 0
		go l.classify(c)
	}
}

func (l *Listener) classify(c net.Conn) {
	if l.timeout > 0 {
		_ = c.SetReadDeadline(time.Now().Add(l.timeout))
	}
	br := bufio.NewReaderSize(c, 1)
	first, err := br.Peek(1)
	if err != nil {
		c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	var out net.Conn = &peekedConn{Conn: c, r: br}
	if first[0] == tlsHandshakeRecord {
		out = tls.Server(out, l.tlsConf)
	}
	select {
	case l.conns <- out:
	case <-l.done:
		c.Close()
	}
}

// Accept returns the next classified connection.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case err := <-l.errs:
		return nil, err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close stops accepting and closes the underlying listener.
func (l *Listener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.done)
		err = l.inner.Close()
	})
	return err
}

// Addr returns the listener address.
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// peekedConn replays bytes buffered while sniffing.
type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekedConn) Read(b []byte) (int, error) { return p.r.Read(b) }
