package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	//tls "github.com/piligo/gmssl"
	tls "crypto/tls"

	tlsgm "github.com/piligo/gmssl"

	slog "github.com/cihub/seelog"

	proxy "github.com/shoulderTang/go-tcp-proxy"
)

var (
	version = "0.0.0-src"
	matchid = uint64(0)
	connid  = uint64(0)
	logger  proxy.ColorLogger

	localAddr  = flag.String("l", ":9999", "local address")
	remoteAddr = flag.String("r", "localhost:80", "remote address")

	pemdir = flag.String("certsdir", "./certs", "client is true,srv is false")

	verbose     = flag.Bool("v", false, "display server actions")
	veryverbose = flag.Bool("vv", false, "display server actions and all tcp data")
	nagles      = flag.Bool("n", false, "disable nagles algorithm")
	hex         = flag.Bool("h", false, "output hex")
	colors      = flag.Bool("c", false, "output ansi colors")
	isTLS       = flag.Bool("tls", false, "remote connection with TLS exposed unencrypted locally")
	isGmTLS     = flag.Bool("gm", false, "GM-TLS")
	match       = flag.String("match", "", "match regex (in the form 'regex')")
	replace     = flag.String("replace", "", "replace regex (in the form 'regex~replacer')")
)

func main() {
	flag.Parse()

	logger := proxy.ColorLogger{
		Verbose: *verbose,
		Color:   *colors,
	}

	logger.Info("go-tcp-proxy (%s) proxing from %v to %v ", version, *localAddr, *remoteAddr)

	laddr, err := net.ResolveTCPAddr("tcp", *localAddr)
	if err != nil {
		logger.Warn("Failed to resolve local address: %s", err)
		os.Exit(1)
	}
	raddr, err := net.ResolveTCPAddr("tcp", *remoteAddr)
	if err != nil {
		logger.Warn("Failed to resolve remote address: %s", err)
		os.Exit(1)
	}

	//change to tls listen
	slog.Info(" server start ")
	var listener net.Listener
	if *isGmTLS {
		cers, err := loadGmCerts(*pemdir)
		if err != nil {
			slog.Error("server_echo : loadCerts err->", err)
			return
		}

		config := &tlsgm.Config{Certificates: cers}
		listener, err = tlsgm.Listen("tcp", *localAddr, config)
		if err != nil {
			logger.Warn("Failed to open local port to listen: %s", err)
			os.Exit(1)
		}
	} else {
		cers, err := loadCerts(*pemdir)
		if err != nil {
			fmt.Println("server_echo : loadCerts err->", err)
			slog.Error("server_echo : loadCerts err->", err)
			return
		}

		config := &tls.Config{Certificates: cers}
		listener, err = tls.Listen("tcp", *localAddr, config)
		if err != nil {
			fmt.Println("Failed to open local port to listen: %s", err)
			logger.Warn("Failed to open local port to listen: %s", err)
			os.Exit(1)
		}
	}

	matcher := createMatcher(*match)
	replacer := createReplacer(*replace)

	if *veryverbose {
		*verbose = true
	}

	for {
		conn, err := listener.Accept()
		//TCPconn := conn.(*net.TCPConn)
		if err != nil {
			fmt.Println("Failed to accept connection '%s'", err)
			logger.Warn("Failed to accept connection '%s'", err)
			continue
		}
		connid++

		var p *proxy.Proxy
		if *isTLS {
			fmt.Println("Unwrapping TLS")
			logger.Info("Unwrapping TLS")
			p = proxy.NewTLS(conn, laddr, raddr, *remoteAddr, *isGmTLS)
		} else {
			p = proxy.New(conn, laddr, raddr)
		}

		p.Matcher = matcher
		p.Replacer = replacer

		p.Nagles = *nagles
		p.OutputHex = *hex
		p.Log = proxy.ColorLogger{
			Verbose:     *verbose,
			VeryVerbose: *veryverbose,
			Prefix:      fmt.Sprintf("Connection #%03d ", connid),
			Color:       *colors,
		}

		go p.Start()
	}
}

func createMatcher(match string) func([]byte) {
	if match == "" {
		return nil
	}
	re, err := regexp.Compile(match)
	if err != nil {
		logger.Warn("Invalid match regex: %s", err)
		return nil
	}

	logger.Info("Matching %s", re.String())
	return func(input []byte) {
		ms := re.FindAll(input, -1)
		for _, m := range ms {
			matchid++
			logger.Info("Match #%d: %s", matchid, string(m))
		}
	}
}

func createReplacer(replace string) func([]byte) []byte {
	if replace == "" {
		return nil
	}
	//split by / (TODO: allow slash escapes)
	parts := strings.Split(replace, "~")
	if len(parts) != 2 {
		logger.Warn("Invalid replace option")
		return nil
	}

	re, err := regexp.Compile(string(parts[0]))
	if err != nil {
		logger.Warn("Invalid replace regex: %s", err)
		return nil
	}

	repl := []byte(parts[1])

	logger.Info("Replacing %s with %s", re.String(), repl)
	return func(input []byte) []byte {
		return re.ReplaceAll(input, repl)
	}
}

func loadGmCerts(pemdir string) ([]tlsgm.Certificate, error) {
	cerfiles := []string{"SS", "CA", "SE"}
	certs := make([]tlsgm.Certificate, 0)
	for _, n := range cerfiles {
		certname := fmt.Sprintf("%s/%s.cert.pem", pemdir, n)
		certkey := fmt.Sprintf("%s/%s.key.pem", pemdir, n)
		cer, err := tlsgm.LoadX509KeyPair(certname, certkey)
		if err != nil {
			fmt.Println("loadGmCerts tlsgm.LoadX509KeyPair err->", err, " name=", certname, " key=", certkey)
			slog.Error("tlsgm.LoadX509KeyPair err->", err, " name=", certname, " key=", certkey)
			return nil, err
		}
		certs = append(certs, cer)
	}
	return certs, nil
}

func loadCerts(pemdir string) ([]tls.Certificate, error) {
	cerfiles := []string{"server"}
	certs := make([]tls.Certificate, 0)
	for _, n := range cerfiles {
		certname := fmt.Sprintf("%s/%s.pem", pemdir, n)
		certkey := fmt.Sprintf("%s/%s.key", pemdir, n)
		cer, err := tls.LoadX509KeyPair(certname, certkey)
		if err != nil {
			fmt.Println("tls.LoadX509KeyPair err->", err, " name=", certname, " key=", certkey)
			slog.Error("tls.LoadX509KeyPair err->", err, " name=", certname, " key=", certkey)
			return nil, err
		}
		certs = append(certs, cer)
	}
	return certs, nil
}
