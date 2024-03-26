/*
Custom HTTP client transport that can handle SiteMinder Isolated Profiles
and SPNEGO.

Currently only adapted for Kerberos 5 on Linux.

Cached Kerberos credentials are required in location
specified by environment variable $KRB5CCNAME
*/

package spnego_mixin

import (
	"bytes"
	"context"
	"crypto/tls"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/mwitkow/go-conntrack"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	pconfig "github.com/prometheus/common/config"
	"golang.org/x/net/publicsuffix"
)

const (
	KRB5_CONF = "/etc/krb5.conf"
)

var (
	jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List}) // TODO : review suffix list to scope cookie
)

type ExporterMetric struct {
	InflightGauge      prometheus.Gauge
	ResponseCount      *prometheus.CounterVec
	DurationHistorgram *prometheus.HistogramVec
}

/*
The Adapter allows us to add more support i.e Windows/SSPI.
See the 'Provder' interface in
https://github.com/dpotapov/go-spnego/blob/master/spnego_gokrb5.go
*/
type Adapter interface {
	SetSPNEGOHeader(*http.Request, bool) error
}

// Implements our Adapter interface for Kerberos 5
type krb5 struct {
	cfg  *config.Config
	clnt *client.Client
}

type spnegoRoundTripper struct {
	rt     http.RoundTripper
	SPN    Adapter
	logger log.Logger
}

func NewClient(cfg pconfig.HTTPClientConfig, name string, moduleMetric *ExporterMetric, logger log.Logger) (*http.Client, error) {
	_ = prometheus.Register(moduleMetric.InflightGauge)
	_ = prometheus.Register(moduleMetric.ResponseCount)
	_ = prometheus.Register(moduleMetric.DurationHistorgram)

	rt, err := NewRoundTripper(cfg, name, logger)
	if err != nil {
		return nil, err
	}
	rt = promhttp.InstrumentRoundTripperInFlight(moduleMetric.InflightGauge,
		promhttp.InstrumentRoundTripperCounter(moduleMetric.ResponseCount,
			promhttp.InstrumentRoundTripperDuration(moduleMetric.DurationHistorgram, rt),
		),
	)

	client := &http.Client{Jar: jar, Transport: rt}
	if !cfg.FollowRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client, nil
}

func NewRoundTripper(cfg pconfig.HTTPClientConfig, name string, logger log.Logger) (http.RoundTripper, error) {
	var dialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	dialContext = conntrack.NewDialContextFunc(conntrack.DialWithTracing(), conntrack.DialWithName(name))

	newRT := func(tlsConfig *tls.Config) (http.RoundTripper, error) {
		// The only timeout we care about is the configured scrape timeout.
		// It is applied on request. So we leave out any timings here.
		var rt http.RoundTripper = &http.Transport{
			Proxy:                 cfg.ProxyConfig.Proxy(),
			ProxyConnectHeader:    cfg.ProxyConfig.GetProxyConnectHeader(),
			MaxIdleConns:          20000,
			MaxIdleConnsPerHost:   1000, // see https://github.com/golang/go/issues/13801
			TLSClientConfig:       tlsConfig,
			DisableCompression:    true,
			DisableKeepAlives:     false,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DialContext:           dialContext,
		}

		rt = NewSpnegoRoundTripper(rt, logger)

		return rt, nil
	}
	tlsConfig, err := pconfig.NewTLSConfig(&cfg.TLSConfig)
	if err != nil {
		return nil, err
	}

	if len(cfg.TLSConfig.CAFile) == 0 {
		// No need for a RoundTripper that reloads the CA file automatically.
		return newRT(tlsConfig)
	}
	return pconfig.NewTLSRoundTripper(tlsConfig, roundTripperSettings(&cfg.TLSConfig), newRT)

}

func roundTripperSettings(c *pconfig.TLSConfig) pconfig.TLSRoundTripperSettings {
	return pconfig.TLSRoundTripperSettings{
		CA:       c.CA,
		CAFile:   c.CAFile,
		Cert:     c.Cert,
		CertFile: c.CertFile,
		Key:      string(c.Key),
		KeyFile:  c.KeyFile,
	}
}

func NewSpnegoRoundTripper(rt http.RoundTripper, logger log.Logger) http.RoundTripper {
	return &spnegoRoundTripper{
		rt:     rt,
		logger: logger,
	}
}

/*
Implements the RoundTripper interface. This is against go/http's recommendation https://pkg.go.dev/net/http#RoundTripper
 1. RoundTrip should not attempt to interpret the response or like handling authentication
 2. RoundTrip should not modify the request
 3. RoundTrip must return err == nil if it obtained a response, regardless of the response's HTTP status code.
    A non-nil err should be reserved for failure to obtain a response.
*/
func (rt *spnegoRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var bodyBytes []byte
	if rt.SPN == nil {
		rt.SPN = NewAdapter()
	}
	if req.Body != nil {
		bodyBytes, _ = ioutil.ReadAll(req.Body)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	}
	resp, err := rt.rt.RoundTrip(req)
	retries := 0
	if resp.StatusCode/100 != 2 {
		level.Warn(rt.logger).Log("msg", "http "+resp.Status, "host", req.URL.Host)
	}
	for (err != nil || shouldRetry(resp)) && retries < 3 {
		time.Sleep(time.Duration(retries*1000000000) * 3 * time.Second)
		if err != nil {
			level.Error(rt.logger).Log("msg", "Error making round trip to server", "Request Host", req.URL.Host, "Request URL", req.URL.Path, "err", err)
		} else {
			if resp.StatusCode == http.StatusUnauthorized {
				if hdr := resp.Header.Get("WWW-Authenticate"); hdr != "" && strings.HasPrefix(hdr, "Negotiate") {
					level.Info(rt.logger).Log("msg", "Negotiate authentication header from server, try to set spnego token", "host", req.URL.Host)
					if rt.SPN.SetSPNEGOHeader(req, true) != nil {
						level.Error(rt.logger).Log("msg", "Error setting spnego token in header", "host", req.URL.Host, "Request URL", req.URL.Path, "err", err)
						retries++
						continue
					}
				}
			}
		}

		if req.Body != nil {
			req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
		}
		level.Info(rt.logger).Log("msg", "Retrying round trip to server", "Request Host", req.URL.Host, "Request URL", req.URL.Path)
		resp, err = rt.rt.RoundTrip(req)
		retries++
	}

	return resp, err
}

func shouldRetry(resp *http.Response) bool {
	if resp.StatusCode == http.StatusBadGateway ||
		resp.StatusCode == http.StatusServiceUnavailable ||
		resp.StatusCode == http.StatusGatewayTimeout ||
		resp.StatusCode == http.StatusUnauthorized {
		return true
	}
	return false
}

// Only Krb5 support today
func NewAdapter() Adapter {
	return &krb5{}
}

// Hostname canonicalization required for proper kerberos principal and service resolution
func canonicalizeHostname(host string) (string, error) {
	h, err := net.LookupCNAME(host)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(h, "."), nil
}

// Read the Kerberos config (should be in /etc/krb5.conf)
func (krb *krb5) readConfig() error {
	var err error

	if krb.cfg != nil {
		return nil
	}

	if krb.cfg, err = config.Load(KRB5_CONF); err != nil {
		return err
	}
	return nil
}

// Create a github.com/jcmturner/gokrb5/v8/client from cached Kerberos credentials.
func (krb *krb5) newClient() error {
	var (
		usr       *user.User
		cacheName string
		cachePath string
		cache     *credentials.CCache
		err       error
	)

	if usr, err = user.Current(); err != nil {
		return err
	}

	cacheName = os.Getenv("KRB5CCNAME")

	if strings.HasPrefix(cacheName, "FILE:") {
		cachePath = strings.SplitN(cacheName, ":", 2)[1]
	} else {
		cachePath = "/tmp/krb5cc_" + usr.Uid
	}

	if cache, err = credentials.LoadCCache(cachePath); err != nil {
		return err
	}

	krb.clnt, err = client.NewFromCCache(cache, krb.cfg, client.DisablePAFXFAST(true))
	return err
}

// Initialization and wraps SetSPNEGOHeader from github.com/jcmturner/gokrb5/v8/spnego
func (krb *krb5) SetSPNEGOHeader(req *http.Request, canonicalize bool) error {
	var (
		host string
		err  error
	)
	host = req.URL.Hostname()
	if canonicalize {
		if host, err = canonicalizeHostname(host); err != nil {
			return err
		}
	}

	if err = krb.readConfig(); err != nil {
		return err
	}

	if err = krb.newClient(); err != nil {
		return err
	}
	return spnego.SetSPNEGOHeader(krb.clnt, req, "HTTP/"+host)
}

