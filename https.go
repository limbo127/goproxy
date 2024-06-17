package goproxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/conduitio/bwlimit"
	"github.com/gorhill/cronexpr"
)

type ConnectActionLiteral int

// maps of struct of mutex and int64 to count the number of connection initiated during a period of time
type ConnMutex struct {
	mutex  *sync.Mutex
	count  int
	period time.Time
}

var mapConnMutex = make(map[string]ConnMutex)
var gconnMutex sync.Mutex // mutex to protect mapConnMutex

const (
	ConnectAccept = iota
	ConnectReject
	ConnectMitm
	ConnectHijack
	ConnectHTTPMitm
	ConnectProxyAuthHijack
)

var (
	OkConnect       = &ConnectAction{Action: ConnectAccept, TLSConfig: TLSConfigFromCA(&GoproxyCa)}
	MitmConnect     = &ConnectAction{Action: ConnectMitm, TLSConfig: TLSConfigFromCA(&GoproxyCa)}
	HTTPMitmConnect = &ConnectAction{Action: ConnectHTTPMitm, TLSConfig: TLSConfigFromCA(&GoproxyCa)}
	RejectConnect   = &ConnectAction{Action: ConnectReject, TLSConfig: TLSConfigFromCA(&GoproxyCa)}
	httpsRegexp     = regexp.MustCompile(`^https:\/\/`)
)

// ConnectAction enables the caller to override the standard connect flow.
// When Action is ConnectHijack, it is up to the implementer to send the
// HTTP 200, or any other valid http response back to the client from within the
// Hijack func
type ConnectAction struct {
	Action    ConnectActionLiteral
	Hijack    func(req *http.Request, client net.Conn, ctx *ProxyCtx)
	TLSConfig func(host string, ctx *ProxyCtx) (*tls.Config, error)
}

func stripPort(s string) string {
	var ix int
	if strings.Contains(s, "[") && strings.Contains(s, "]") {
		//ipv6 : for example : [2606:4700:4700::1111]:443

		//strip '[' and ']'
		s = strings.ReplaceAll(s, "[", "")
		s = strings.ReplaceAll(s, "]", "")

		ix = strings.LastIndexAny(s, ":")
		if ix == -1 {
			return s
		}
	} else {
		//ipv4
		ix = strings.IndexRune(s, ':')
		if ix == -1 {
			return s
		}

	}
	return s[:ix]
}

func (proxy *ProxyHttpServer) dial(network, addr string) (c net.Conn, err error) {
	if proxy.Tr.Dial != nil {
		return proxy.Tr.Dial(network, addr)
	}
	return net.Dial(network, addr)
}

func (proxy *ProxyHttpServer) connectDial(ctx *ProxyCtx, network, addr string) (c net.Conn, err error) {
	if proxy.ConnectDialWithReq == nil && proxy.ConnectDial == nil {
		return proxy.dial(network, addr)
	}

	if proxy.ConnectDialWithReq != nil {
		return proxy.ConnectDialWithReq(ctx.Req, network, addr)
	}
	return proxy.ConnectDial(network, addr)
}

type halfClosable interface {
	net.Conn
	CloseWrite() error
	CloseRead() error
}

var _ halfClosable = (*net.TCPConn)(nil)

func FindRightBandwidthLimit(band BandwidthConfiguration) (BandwidthLimit, bool) {
	gconnMutex.Lock()
	connMutex, ok := mapConnMutex[band.Host]
	defer gconnMutex.Unlock()
	if !ok {
		connMutex = ConnMutex{
			mutex:  &sync.Mutex{},
			count:  1,
			period: time.Now(),
		}
		mapConnMutex[band.Host] = connMutex
	} else {
		if time.Since(connMutex.period) > 1*time.Second {
			connMutex.count = 0
			connMutex.period = time.Now()
		}
		//connMutex.mutex.Lock()
		connMutex.count++
		mapConnMutex[band.Host] = connMutex
		//connMutex.mutex.Unlock()
	}
	var result BandwidthLimit
	for _, value := range band.Limits {
		if ParseAndNextStart(value.Crontab) >= time.Now().Unix() && ParseAndNextStart(value.Crontab) <= time.Now().Add(1*time.Minute).Unix() {
			result = value
			break
			//return value, true
		}
	}
	if result.Crontab == "" {
		return BandwidthLimit{}, false
	}
	time.Sleep(1 * time.Second)
	// create a new  BandwidthLimitwith BandwidthLimit.WriteLimit and BandwidthLimit.ReadLimit divide by the connMutex.count
	// return the new BandwidthLimit
	writeLimit := result.WriteLimit
	readLimit := result.ReadLimit
	if connMutexN, ok := mapConnMutex[band.Host]; ok {
		writeLimit = result.WriteLimit / bwlimit.Byte(connMutexN.count)
		readLimit = result.ReadLimit / bwlimit.Byte(connMutexN.count)
	}

	return BandwidthLimit{WriteLimit: writeLimit, ReadLimit: readLimit}, true

}

func ParseAndNextStart(crontab string) int64 {

	if location, err := time.LoadLocation("UTC"); err == nil {
		now := time.Now()
		localizedNow := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), 0, 0, location)
		_, offset := localizedNow.Zone()
		if crontab != "" {
			nextTime := cronexpr.MustParse(crontab).Next(time.Now())
			utcTime := nextTime.Add((-time.Duration(offset)) * time.Second)
			return (utcTime.Unix())
		}
	}
	return 0
}

func (proxy *ProxyHttpServer) handleHttps(w http.ResponseWriter, r *http.Request) {

	ctx := &ProxyCtx{Req: r, Session: atomic.AddInt64(&proxy.sess, 1), Proxy: proxy, certStore: proxy.CertStore}

	hij, ok := w.(http.Hijacker)
	if !ok {
		panic("httpserver does not support hijacking")
	}

	proxyClient, _, e := hij.Hijack()
	if e != nil {
		panic("Cannot hijack connection " + e.Error())
	}

	//ctx.Logf("Running %d CONNECT handlers", len(proxy.httpsHandlers))
	todo, host := OkConnect, r.URL.Host
	for _, h := range proxy.httpsHandlers {
		newtodo, newhost := h.HandleConnect(host, ctx)
		// If found a result, break the loop immediately
		if newtodo != nil {
			todo, host = newtodo, newhost
			//ctx.Logf("on %dth handler: %v %s", i, todo, host)
			break
		}
	}
	switch todo.Action {
	case ConnectAccept:
		if !hasPort.MatchString(host) {
			host += ":80"
		}
		var _host string
		var targetSiteCon net.Conn
		var err error
		ctx.Logf("====Connect to host %s", host)

		// for all key of proxy.StreamBandwidth , create a regexp of the map key to match the host
		for key := range proxy.StreamBandwidth {
			if re, err := regexp.Compile(key); err == nil {
				if re.MatchString(host) {
					_host = key
					ctx.Logf("====Find a match host %s for key:%v", host, key)
					break
				}
			}
		}

		value, ok := proxy.StreamBandwidth[_host]

		if ok {
			// current unixTime in value.Crontab must be equal with 1 minutes delay with ciurrent time
			if limit, b := FindRightBandwidthLimit(value); b {
				targetSiteCon, err = proxy.connectDial(ctx, "tcp", host)
				// value is a struct with writelimit and readlimit int64
				targetSiteCon = bwlimit.NewConn(targetSiteCon, limit.WriteLimit, limit.ReadLimit)
				ctx.Logf("====Set bandwidth limit for host %s, writeLimit: %d, readLimit: %d", host, limit.WriteLimit, limit.ReadLimit)
			} else {
				ctx.Logf("====Not set bandwidth limit for host %s because of not applicable crontab ", host)
				targetSiteCon, err = proxy.connectDial(ctx, "tcp", host)
			}
		} else {
			targetSiteCon, err = proxy.connectDial(ctx, "tcp", host)
		}
		if err != nil {
			ctx.Warnf("Error dialing to %s: %s", host, err.Error())
			httpError(proxyClient, ctx, err)
			return
		}
		//ctx.Logf("Accepting CONNECT to %s", host)
		proxyClient.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))

		proxyClientTCP, clientOK := proxyClient.(halfClosable)

		if clientOK {
			go copyAndCloseS(ctx, targetSiteCon, proxyClientTCP)
			go copyAndCloseS(ctx, proxyClientTCP, targetSiteCon)
		} else {
			go func() {
				var wg sync.WaitGroup
				wg.Add(2)
				go copyOrWarn(ctx, targetSiteCon, proxyClient, &wg)
				go copyOrWarn(ctx, proxyClient, targetSiteCon, &wg)
				wg.Wait()
				proxyClient.Close()
				targetSiteCon.Close()

			}()
		}

	case ConnectHijack:
		todo.Hijack(r, proxyClient, ctx)
	case ConnectHTTPMitm:
		proxyClient.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
		ctx.Logf("Assuming CONNECT is plain HTTP tunneling, mitm proxying it")
		targetSiteCon, err := proxy.connectDial(ctx, "tcp", host)
		if err != nil {
			ctx.Warnf("Error dialing to %s: %s", host, err.Error())
			return
		}
		for {
			client := bufio.NewReader(proxyClient)
			remote := bufio.NewReader(targetSiteCon)
			req, err := http.ReadRequest(client)
			if err != nil && err != io.EOF {
				ctx.Warnf("cannot read request of MITM HTTP client: %+#v", err)
			}
			if err != nil {
				return
			}
			req, resp := proxy.filterRequest(req, ctx)
			if resp == nil {
				if err := req.Write(targetSiteCon); err != nil {
					httpError(proxyClient, ctx, err)
					return
				}
				resp, err = http.ReadResponse(remote, req)
				if err != nil {
					httpError(proxyClient, ctx, err)
					return
				}
				defer resp.Body.Close()
			}
			resp = proxy.filterResponse(resp, ctx)
			if err := resp.Write(proxyClient); err != nil {
				httpError(proxyClient, ctx, err)
				return
			}
		}
	case ConnectMitm:
		proxyClient.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
		ctx.Logf("Assuming CONNECT is TLS, mitm proxying it")
		// this goes in a separate goroutine, so that the net/http server won't think we're
		// still handling the request even after hijacking the connection. Those HTTP CONNECT
		// request can take forever, and the server will be stuck when "closed".
		// TODO: Allow Server.Close() mechanism to shut down this connection as nicely as possible
		tlsConfig := defaultTLSConfig
		if todo.TLSConfig != nil {
			var err error
			tlsConfig, err = todo.TLSConfig(host, ctx)
			if err != nil {
				httpError(proxyClient, ctx, err)
				return
			}
		}
		go func() {
			//TODO: cache connections to the remote website
			rawClientTls := tls.Server(proxyClient, tlsConfig)
			if err := rawClientTls.Handshake(); err != nil {
				ctx.Warnf("Cannot handshake client %v %v", r.Host, err)
				return
			}
			defer rawClientTls.Close()
			clientTlsReader := bufio.NewReader(rawClientTls)
			for !isEof(clientTlsReader) {
				req, err := http.ReadRequest(clientTlsReader)
				var ctx = &ProxyCtx{Req: req, Session: atomic.AddInt64(&proxy.sess, 1), Proxy: proxy, UserData: ctx.UserData}
				if err != nil && err != io.EOF {
					return
				}
				if err != nil {
					ctx.Warnf("Cannot read TLS request from mitm'd client %v %v", r.Host, err)
					return
				}
				req.RemoteAddr = r.RemoteAddr // since we're converting the request, need to carry over the original connecting IP as well
				ctx.Logf("req %v", r.Host)

				if !httpsRegexp.MatchString(req.URL.String()) {
					req.URL, err = url.Parse("https://" + r.Host + req.URL.String())
				}

				// Bug fix which goproxy fails to provide request
				// information URL in the context when does HTTPS MITM
				ctx.Req = req

				req, resp := proxy.filterRequest(req, ctx)
				if resp == nil {
					if isWebSocketRequest(req) {
						ctx.Logf("Request looks like websocket upgrade.")
						proxy.serveWebsocketTLS(ctx, w, req, tlsConfig, rawClientTls)
						return
					}
					if err != nil {
						if req.URL != nil {
							ctx.Warnf("Illegal URL %s", "https://"+r.Host+req.URL.Path)
						} else {
							ctx.Warnf("Illegal URL %s", "https://"+r.Host)
						}
						return
					}
					removeProxyHeaders(ctx, req)
					resp, err = func() (*http.Response, error) {
						// explicitly discard request body to avoid data races in certain RoundTripper implementations
						// see https://github.com/golang/go/issues/61596#issuecomment-1652345131
						defer req.Body.Close()
						return ctx.RoundTrip(req)
					}()
					if err != nil {
						ctx.Warnf("Cannot read TLS response from mitm'd server %v", err)
						return
					}
					ctx.Logf("resp %v", resp.Status)
				}
				resp = proxy.filterResponse(resp, ctx)
				defer resp.Body.Close()

				text := resp.Status
				statusCode := strconv.Itoa(resp.StatusCode) + " "
				if strings.HasPrefix(text, statusCode) {
					text = text[len(statusCode):]
				}
				// always use 1.1 to support chunked encoding
				if _, err := io.WriteString(rawClientTls, "HTTP/1.1"+" "+statusCode+text+"\r\n"); err != nil {
					ctx.Warnf("Cannot write TLS response HTTP status from mitm'd client: %v", err)
					return
				}

				if resp.Request.Method == "HEAD" {
					// don't change Content-Length for HEAD request
				} else {
					// Since we don't know the length of resp, return chunked encoded response
					// TODO: use a more reasonable scheme
					resp.Header.Del("Content-Length")
					resp.Header.Set("Transfer-Encoding", "chunked")
				}
				// Force connection close otherwise chrome will keep CONNECT tunnel open forever
				resp.Header.Set("Connection", "close")
				if err := resp.Header.Write(rawClientTls); err != nil {
					ctx.Warnf("Cannot write TLS response header from mitm'd client: %v", err)
					return
				}
				if _, err = io.WriteString(rawClientTls, "\r\n"); err != nil {
					ctx.Warnf("Cannot write TLS response header end from mitm'd client: %v", err)
					return
				}

				if resp.Request.Method == "HEAD" {
					// Don't write out a response body for HEAD request
				} else {
					chunked := newChunkedWriter(rawClientTls)
					if _, err := io.Copy(chunked, resp.Body); err != nil {
						ctx.Warnf("Cannot write TLS response body from mitm'd client: %v", err)
						return
					}
					if err := chunked.Close(); err != nil {
						ctx.Warnf("Cannot write TLS chunked EOF from mitm'd client: %v", err)
						return
					}
					if _, err = io.WriteString(rawClientTls, "\r\n"); err != nil {
						ctx.Warnf("Cannot write TLS response chunked trailer from mitm'd client: %v", err)
						return
					}
				}
			}
			ctx.Logf("Exiting on EOF")
		}()
	case ConnectProxyAuthHijack:
		proxyClient.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n"))
		todo.Hijack(r, proxyClient, ctx)
	case ConnectReject:
		if ctx.Resp != nil {
			if err := ctx.Resp.Write(proxyClient); err != nil {
				ctx.Warnf("Cannot write response that reject http CONNECT: %v", err)
			}
		}
		proxyClient.Close()
	}
}

func httpError(w io.WriteCloser, ctx *ProxyCtx, err error) {
	errStr := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(err.Error()), err.Error())
	if _, err := io.WriteString(w, errStr); err != nil {
		ctx.Warnf("Error responding to client: %s", err)
	}
	if err := w.Close(); err != nil {
		ctx.Warnf("Error closing client connection: %s", err)
	}
}

func copyOrWarn(ctx *ProxyCtx, dst io.Writer, src io.Reader, wg *sync.WaitGroup) {
	if _, err := io.Copy(dst, src); err != nil {
		ctx.Warnf("===>Error copying to client: %s", err)
	}
	wg.Done()
}

func copyAndCloseS(ctx *ProxyCtx, dst net.Conn, src net.Conn) {
	if _, err := io.Copy(dst, src); err != nil {
		//ctx.Warnf("<=====Error copying to client: %s", err)
	}

	// test if dst is a bwlimit.Conn
	if _, ok := dst.(*bwlimit.Conn); ok {
		dst.(*bwlimit.Conn).Conn.(*net.TCPConn).CloseWrite()
	}
	// test if src is a bwlimit.Conn
	if _, ok := src.(*bwlimit.Conn); ok {
		src.(*bwlimit.Conn).Conn.(*net.TCPConn).CloseRead()
	}
	// test if dst is a halfClosable
	if dst, ok := dst.(halfClosable); ok {
		dst.CloseWrite()
	}
	// test if src is a halfClosable
	if src, ok := src.(halfClosable); ok {
		src.CloseRead()
	}

}

func copyAndClose(ctx *ProxyCtx, dst, src halfClosable) {
	if _, err := io.Copy(dst, src); err != nil {
		//ctx.Warnf("<=====Error copying to client: %s", err)
	}

	dst.CloseWrite()
	src.CloseRead()
}

func dialerFromEnv(proxy *ProxyHttpServer) func(network, addr string) (net.Conn, error) {
	https_proxy := os.Getenv("HTTPS_PROXY")
	if https_proxy == "" {
		https_proxy = os.Getenv("https_proxy")
	}
	if https_proxy == "" {
		return nil
	}
	return proxy.NewConnectDialToProxy(https_proxy)
}

func (proxy *ProxyHttpServer) NewConnectDialToProxy(https_proxy string) func(network, addr string) (net.Conn, error) {
	return proxy.NewConnectDialToProxyWithHandler(https_proxy, nil)
}

func (proxy *ProxyHttpServer) NewConnectDialToProxyWithHandler(https_proxy string, connectReqHandler func(req *http.Request)) func(network, addr string) (net.Conn, error) {
	u, err := url.Parse(https_proxy)
	if err != nil {
		return nil
	}
	if u.Scheme == "" || u.Scheme == "http" {
		if !strings.ContainsRune(u.Host, ':') {
			u.Host += ":80"
		}
		return func(network, addr string) (net.Conn, error) {
			connectReq := &http.Request{
				Method: "CONNECT",
				URL:    &url.URL{Opaque: addr},
				Host:   addr,
				Header: make(http.Header),
			}
			if connectReqHandler != nil {
				connectReqHandler(connectReq)
			}
			c, err := proxy.dial(network, u.Host)
			if err != nil {
				return nil, err
			}
			connectReq.Write(c)
			// Read response.
			// Okay to use and discard buffered reader here, because
			// TLS server will not speak until spoken to.
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, connectReq)
			if err != nil {
				c.Close()
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				resp, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					return nil, err
				}
				c.Close()
				return nil, errors.New("proxy refused connection" + string(resp))
			}
			return c, nil
		}
	}
	if u.Scheme == "https" || u.Scheme == "wss" {
		if !strings.ContainsRune(u.Host, ':') {
			u.Host += ":443"
		}
		return func(network, addr string) (net.Conn, error) {
			c, err := proxy.dial(network, u.Host)
			if err != nil {
				return nil, err
			}
			c = tls.Client(c, proxy.Tr.TLSClientConfig)
			connectReq := &http.Request{
				Method: "CONNECT",
				URL:    &url.URL{Opaque: addr},
				Host:   addr,
				Header: make(http.Header),
			}
			if connectReqHandler != nil {
				connectReqHandler(connectReq)
			}
			connectReq.Write(c)
			// Read response.
			// Okay to use and discard buffered reader here, because
			// TLS server will not speak until spoken to.
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, connectReq)
			if err != nil {
				c.Close()
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 500))
				if err != nil {
					return nil, err
				}
				c.Close()
				return nil, errors.New("proxy refused connection" + string(body))
			}
			return c, nil
		}
	}
	return nil
}

func TLSConfigFromCA(ca *tls.Certificate) func(host string, ctx *ProxyCtx) (*tls.Config, error) {
	return func(host string, ctx *ProxyCtx) (*tls.Config, error) {
		var err error
		var cert *tls.Certificate

		hostname := stripPort(host)
		config := defaultTLSConfig.Clone()
		ctx.Logf("signing for %s", stripPort(host))

		genCert := func() (*tls.Certificate, error) {
			return signHost(*ca, []string{hostname})
		}
		if ctx.certStore != nil {
			cert, err = ctx.certStore.Fetch(hostname, genCert)
		} else {
			cert, err = genCert()
		}

		if err != nil {
			ctx.Warnf("Cannot sign host certificate with provided CA: %s", err)
			return nil, err
		}

		config.Certificates = append(config.Certificates, *cert)
		return config, nil
	}
}
