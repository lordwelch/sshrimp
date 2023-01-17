package sshrimpagent

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/ssh"

	"git.narnian.us/lordwelch/sshrimp/internal/config"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/pkg/http"
	"github.com/zitadel/oidc/pkg/oidc"
	"golang.org/x/exp/slices"
)

var (
	key = []byte(uuid.New().String())[:16]
)

type OidcClient struct {
	ListenAddress string
	*http.Server
	oidcMux     *http.ServeMux
	OIDCToken   chan *oidc.Tokens
	Certificate *ssh.Certificate
	*config.SSHrimp
}

func newOIDCClient(c *config.SSHrimp) (*OidcClient, error) {
	if len(c.Agent.Scopes) < 1 {
		c.Agent.Scopes = []string{"openid", "email", "profile"}
	}
	if !slices.Contains(c.Agent.Scopes, "openid") {
		c.Agent.Scopes = append([]string{"scopes"}, c.Agent.Scopes...)
	}

	token_chan := make(chan *oidc.Tokens)

	oidcMux := http.NewServeMux()
	return &OidcClient{
		oidcMux: oidcMux,
		Server: &http.Server{
			Addr:              fmt.Sprintf("localhost:%d", c.Agent.Port),
			Handler:           oidcMux,
			ReadTimeout:       time.Minute / 2,
			ReadHeaderTimeout: time.Minute / 2,
			WriteTimeout:      time.Minute / 2,
			IdleTimeout:       time.Minute / 2,
		},
		OIDCToken:   token_chan,
		Certificate: &ssh.Certificate{},
		SSHrimp:     c,
	}, nil
}

func (o *OidcClient) baseURI() url.URL {
	return url.URL{
		Scheme: "http",
		Host:   o.Addr,
	}
}

func (o *OidcClient) ListenAndServe() error {
	ln, err := net.Listen("tcp", o.Addr)
	if err != nil {
		return err
	}
	o.Addr = ln.Addr().String()
	if err = o.setupHandlers(); err != nil {
		return err
	}
	return o.Server.Serve(ln)
}

func (o *OidcClient) setupHandlers() error {
	redirectURI := o.baseURI()
	redirectURI.Path = "/auth/callback"
	successURI := o.baseURI()
	successURI.Path = "/success"
	// failURI := o.baseURI()
	// failURI.RawQuery = url.Values{"auth":[]string{"fail"}}.Encode()

	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
	}
	if o.Agent.ClientSecret == "" {
		options = append(options, rp.WithPKCE(cookieHandler))
	}
	if o.Agent.KeyPath != "" {
		options = append(options, rp.WithJWTProfile(rp.SignerFromKeyPath(o.Agent.KeyPath)))
	}

	provider, err := rp.NewRelyingPartyOIDC(o.Agent.ProviderURL, o.Agent.ClientID, o.Agent.ClientSecret, redirectURI.String(), o.Agent.Scopes, options...)
	if err != nil {
		return fmt.Errorf("error creating provider: %w", err)
	}

	// generate some state (representing the state of the user in your application,
	// e.g. the page where he was before sending him to login
	state := func() string {
		return uuid.New().String()
	}

	// register the AuthURLHandler at your preferred path
	// the AuthURLHandler creates the auth request and redirects the user to the auth server
	// including state handling with secure cookie and the possibility to use PKCE
	o.oidcMux.Handle("/login", rp.AuthURLHandler(state, provider))
	o.oidcMux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o.Certificate != nil && o.Certificate.SignatureKey != nil {
			fmt.Fprintf(w, "The SSH CA currently in use is:\n%s", ssh.MarshalAuthorizedKey(o.Certificate.SignatureKey))
			Log.Printf("The SSH CA currently in use is:\n%s", ssh.MarshalAuthorizedKey(o.Certificate.SignatureKey))
		}
	}))
	o.oidcMux.Handle(successURI.Path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Return to the CLI.")
		if o.Certificate != nil && o.Certificate.SignatureKey != nil {
			fmt.Fprintf(w, "The SSH CA currently in use is: %s", ssh.MarshalAuthorizedKey(o.Certificate.SignatureKey))
			Log.Printf("The SSH CA currently in use is:\n%s", ssh.MarshalAuthorizedKey(o.Certificate.SignatureKey))
		}
	}))

	// for demonstration purposes the returned userinfo response is written as JSON object onto response
	marshalUserinfo := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens, state string, rp rp.RelyingParty) {
		o.OIDCToken <- tokens
		w.Header().Add("location", successURI.String())
		w.WriteHeader(301)
	}

	// register the CodeExchangeHandler at the callbackPath
	// the CodeExchangeHandler handles the auth response, creates the token request and calls the callback function
	// with the returned tokens from the token endpoint
	o.oidcMux.Handle(redirectURI.Path, rp.CodeExchangeHandler(marshalUserinfo, provider))
	return nil
}
