package network

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type AutoHttpsConn struct {
	net.Conn

	firstBuf []byte
	bufStart int

	readRequestOnce sync.Once
}

func NewAutoHttpsConn(conn net.Conn) net.Conn {
	return &AutoHttpsConn{
		Conn: conn,
	}
}

// probeTimeout bounds the initial read used to tell a plain HTTP request from a
// TLS handshake. This read happens before net/http ever sees the connection, so
// the server's ReadHeaderTimeout does not cover it: without a deadline a client
// that connects and sends nothing parks a goroutine here indefinitely, which is
// an unauthenticated way to exhaust the process.
const probeTimeout = 15 * time.Second

func (c *AutoHttpsConn) readRequest() bool {
	if err := c.Conn.SetReadDeadline(time.Now().Add(probeTimeout)); err != nil {
		c.firstBuf = nil
		return false
	}
	// Clear the deadline again so it does not apply to the TLS handshake or to
	// any later read on this connection.
	defer func() { _ = c.Conn.SetReadDeadline(time.Time{}) }()

	buf := make([]byte, 2048)
	n, err := c.Conn.Read(buf)
	if n > 0 {
		c.firstBuf = buf[:n]
	} else {
		// Nothing to replay. Leave firstBuf nil so Read falls through to the
		// underlying connection and surfaces the error instead of spinning on
		// a zero-length buffer.
		c.firstBuf = nil
	}
	if err != nil {
		return false
	}
	reader := bytes.NewReader(c.firstBuf)
	bufReader := bufio.NewReader(reader)
	request, err := http.ReadRequest(bufReader)
	if err != nil {
		return false
	}
	resp := http.Response{
		Header: http.Header{},
	}
	resp.StatusCode = http.StatusTemporaryRedirect
	location := fmt.Sprintf("https://%v%v", request.Host, request.RequestURI)
	resp.Header.Set("Location", location)
	resp.Write(c.Conn)
	c.Close()
	c.firstBuf = nil
	return true
}

func (c *AutoHttpsConn) Read(buf []byte) (int, error) {
	c.readRequestOnce.Do(func() {
		c.readRequest()
	})

	if c.firstBuf != nil {
		n := copy(buf, c.firstBuf[c.bufStart:])
		c.bufStart += n
		if c.bufStart >= len(c.firstBuf) {
			c.firstBuf = nil
		}
		return n, nil
	}

	return c.Conn.Read(buf)
}
