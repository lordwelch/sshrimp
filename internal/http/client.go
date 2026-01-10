package http

import (
	"net"
	"net/http"
	"time"
)

type Transport struct {
	http.RoundTripper
	UserAgent string
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", t.UserAgent)
	}
	if t.RoundTripper == nil {
		d := &net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		t.RoundTripper = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           d.DialContext,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   2 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}
	return t.RoundTripper.RoundTrip(req)
}

var Client = &http.Client{
	Transport: &Transport{UserAgent: "sshrimp-agent"},
	Timeout:   10 * time.Second,
}
