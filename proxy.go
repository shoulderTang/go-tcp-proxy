package proxy

import (
	"fmt"
	"io"
	"net"

	tls "crypto/tls"

	slog "github.com/cihub/seelog"
	tlsgm "github.com/piligo/gmssl"
)

// Proxy - Manages a Proxy connection, piping data between local and remote.
type Proxy struct {
	sentBytes     uint64
	receivedBytes uint64
	laddr, raddr  *net.TCPAddr
	lconn, rconn  io.ReadWriteCloser
	erred         bool
	errsig        chan bool
	tlsUnwrapp    bool
	isGmtls       bool
	tlsAddress    string

	Matcher  func([]byte)
	Replacer func([]byte) []byte

	// Settings
	Nagles    bool
	Log       Logger
	OutputHex bool
}

// New - Create a new Proxy instance. Takes over local connection passed in,
// and closes it when finished.
func New(lconn io.ReadWriteCloser, laddr, raddr *net.TCPAddr) *Proxy {
	return &Proxy{
		lconn:  lconn,
		laddr:  laddr,
		raddr:  raddr,
		erred:  false,
		errsig: make(chan bool),
		Log:    NullLogger{},
	}
}

// NewTLSUnwrapped - Create a new Proxy instance with a remote TLS server for
// which we want to unwrap the TLS to be able to connect without encryption
// locally
func NewTLS(lconn io.ReadWriteCloser, laddr, raddr *net.TCPAddr, addr string, isGm bool) *Proxy {
	p := New(lconn, laddr, raddr)
	p.tlsUnwrapp = true
	p.isGmtls = isGm
	p.tlsAddress = addr
	return p
}

type setNoDelayer interface {
	SetNoDelay(bool) error
}

// Start - open connection to remote and start proxying data.
func (p *Proxy) Start() {
	defer p.lconn.Close()

	var err error
	//connect to remote
	if p.tlsUnwrapp {
		if p.isGmtls {
			conf := &tlsgm.Config{
				InsecureSkipVerify: true, //为true 接收任何服务端的证书不做校验
			}
			p.rconn, err = tlsgm.Dial("tcp", p.tlsAddress, conf)
			if err != nil {
				fmt.Println("Dial ERR->", err)
				slog.Info("Dial ERR->", err)
				return
			}
			slog.Info("Client: gmtsl connect remote addr sucess->", p.tlsAddress)
		} else {
			conf := &tls.Config{
				InsecureSkipVerify: true, //为true 接收任何服务端的证书不做校验
			}
			p.rconn, err = tls.Dial("tcp", p.tlsAddress, conf)
			if err != nil {
				fmt.Println("Dial ERR->", err)
				slog.Info("Dial ERR->", err)
				return
			}
			slog.Info("Client: tsl connect remote addr sucess->", p.tlsAddress)
		}
	} else {
		p.rconn, err = net.DialTCP("tcp", nil, p.raddr)
	}
	if err != nil {
		fmt.Println("Remote connection failed: %s", err)
		p.Log.Warn("Remote connection failed: %s", err)
		return
	}
	defer p.rconn.Close()

	//nagles?
	if p.Nagles {
		if conn, ok := p.lconn.(setNoDelayer); ok {
			conn.SetNoDelay(true)
		}
		if conn, ok := p.rconn.(setNoDelayer); ok {
			conn.SetNoDelay(true)
		}
	}

	//display both ends
	p.Log.Info("Opened %s >>> %s", p.laddr.String(), p.raddr.String())
	fmt.Println("Opened %s >>> %s", p.laddr.String(), p.raddr.String())

	//bidirectional copy
	//go p.pipe(p.lconn, p.rconn)
	//go p.pipe(p.rconn, p.lconn)

	p.Pipe(p.lconn, p.rconn)
	p.Pipe(p.rconn, p.lconn)

	//wait for close...
	<-p.errsig
	p.Log.Info("Closed (%d bytes sent, %d bytes recieved)", p.sentBytes, p.receivedBytes)
}

func (p *Proxy) err(s string, err error) {
	if p.erred {
		return
	}
	if err != io.EOF {
		p.Log.Warn(s, err)
	}
	p.errsig <- true
	p.erred = true
}

/*
func (p *Proxy) pipe(src, dst io.ReadWriter) {
	islocal := src == p.lconn

	var dataDirection string
	if islocal {
		dataDirection = ">>> %d bytes sent%s"
	} else {
		dataDirection = "<<< %d bytes recieved%s"
	}

	var byteFormat string
	if p.OutputHex {
		byteFormat = "%x"
	} else {
		byteFormat = "%s"
	}

	//directional copy (64k buffer)
	buff := make([]byte, 0xffff)
	for {
		n, err := src.Read(buff)
		if err != nil {
			p.err("Read failed '%s'\n", err)
			return
		}
		b := buff[:n]

		//execute match
		if p.Matcher != nil {
			p.Matcher(b)
		}

		//execute replace
		if p.Replacer != nil {
			b = p.Replacer(b)
		}

		//show output
		p.Log.Debug(dataDirection, n, "")
		p.Log.Trace(byteFormat, b)

		//write out result
		n, err = dst.Write(b)
		if err != nil {
			p.err("Write failed '%s'\n", err)
			return
		}
		if islocal {
			p.sentBytes += uint64(n)
		} else {
			p.receivedBytes += uint64(n)
		}
	}
}
*/

func (p *Proxy) chanFromConn(conn io.ReadWriter) chan []byte {
	c := make(chan []byte)

	go func() {
		b := make([]byte, 0xffff)

		for {
			n, err := conn.Read(b)
			if n > 0 {
				res := make([]byte, n)
				// Copy the buffer so it doesn't get changed while read by the recipient.
				copy(res, b[:n])
				c <- res
			}
			if err != nil {
				c <- nil
				p.err("Read failed '%s'\n", err)
				break
			}
		}
	}()

	return c
}

func (p *Proxy) Pipe(conn1, conn2 io.ReadWriter) {
	chan1 := p.chanFromConn(conn1)
	chan2 := p.chanFromConn(conn2)

	for {
		select {
		case b1 := <-chan1:
			if b1 == nil {
				return
			} else {
				conn2.Write(b1)
			}
		case b2 := <-chan2:
			if b2 == nil {
				return
			} else {
				conn1.Write(b2)
			}
		}
	}
}
