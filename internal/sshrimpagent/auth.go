package sshrimpagent

import (
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"

	"slices"

	"gitea.narnian.us/lordwelch/sshrimp/internal/config"
	sshrimp_http "gitea.narnian.us/lordwelch/sshrimp/internal/http"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/pkg/http"
	"github.com/zitadel/oidc/pkg/oidc"
)

var hashKey = []byte(uuid.New().String())[:16]

type OidcClient struct {
	ListenAddress string
	*http.Server
	oidcMux     *http.ServeMux
	OIDCToken   chan *oidc.Tokens
	Certificate *ssh.Certificate
	rpDate      time.Time
	*config.SSHrimp
	provider *Provider
	pkce string
}

func newOIDCClient(c *config.SSHrimp) (*OidcClient, error) {
	if len(c.Agent.Scopes) < 1 {
		c.Agent.Scopes = []string{"openid", "email", "profile"}
	}
	if !slices.Contains(c.Agent.Scopes, "openid") {
		c.Agent.Scopes = append([]string{"scopes"}, c.Agent.Scopes...)
	}

	token := make(chan *oidc.Tokens)

	redirectURI := url.URL{
		Scheme: "sshrimp",
		// Host:   fmt.Sprintf("127.0.0.1:%d", c.Agent.Port),
	}
	redirectURI.Path = "/auth/callback"
	// oidcMux := http.NewServeMux()
	client := &OidcClient{
		// oidcMux: oidcMux,
		// Server: &http.Server{
		// 	Addr:              fmt.Sprintf("localhost:%d", c.Agent.Port),
		// 	Handler:           oidcMux,
		// 	ReadTimeout:       time.Minute / 2,
		// 	ReadHeaderTimeout: time.Minute / 2,
		// 	WriteTimeout:      time.Minute / 2,
		// 	IdleTimeout:       time.Minute / 2,
		// },
		OIDCToken:   token,
		Certificate: &ssh.Certificate{},
		SSHrimp:     c,
		provider: &Provider{
			providerURL:   c.Agent.ProviderURL,
			clientID:      c.Agent.ClientID,
			clientSecret:  c.Agent.ClientSecret,
			scopes:        c.Agent.Scopes,
			redirectURI:   redirectURI,
			cookieHandler: httphelper.NewCookieHandler(hashKey, nil),
		},
	}
	client.provider.updateRP()
	return client, nil
}

func (o *OidcClient) baseURI() url.URL {
	return url.URL{
		Scheme: "http",
		Host:   o.Addr,
	}
}

func (o *OidcClient) ListenAndServe() error {
	// ln, err := net.Listen("tcp", o.Addr)
	// if err != nil {
	// 	return err
	// }
	// o.Addr = ln.Addr().String()
	// if err = o.setupHandlers(); err != nil {
	// 	return err
	// }
	// return o.Serve(ln)
	return nil
}

func (o *OidcClient) setupHandlers() error {
	// successURI := o.baseURI()
	// successURI.Path = "/success"
	// var CAKey []byte
	// resp, err := sshrimp_http.Client.Get(o.Agent.CAUrls[0])
	// if err == nil && resp.Header.Get("Content-Type") == "text/x-ssh-public-key" {
	// 	CAKey, err = io.ReadAll(resp.Body)
	// 	if err != nil {
	// 		CAKey = []byte{}
	// 	}
	// }
	// generate some state (representing the state of the user in your application,
	// e.g. the page where he was before sending him to login
	// state := func() string {
	// 	return uuid.New().String()
	// }

	// register the AuthURLHandler at your preferred path
	// the AuthURLHandler creates the auth request and redirects the user to the auth server
	// including state handling with secure cookie and the possibility to use PKCE
	// o.oidcMux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 	if o.Certificate != nil && o.Certificate.SignatureKey != nil {
	// 		key := ssh.MarshalAuthorizedKey(o.Certificate.SignatureKey)
	// 		if len(CAKey) < 3 {
	// 			CAKey = key
	// 		}
	// 		if !slices.Equal(key, CAKey) {
	// 			Log.Errorf("Certificate Authority key has changed from %#v to %#v", string(CAKey), string(key))
	// 			fmt.Fprintf(w, "\n\nCertificate Authority key has changed from \n%#v\nto \n%#v", string(CAKey), string(key))
	// 		}
	// 	}
	// 	fmt.Fprintf(w, "The SSH CA currently in use is:\n%s", CAKey)
	// 	Log.Printf("The SSH CA currently in use is:\n%s", CAKey)
	// }))
	// o.oidcMux.Handle(successURI.Path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 	fmt.Fprintln(w, "Return to the CLI.")
	// 	if o.Certificate != nil && o.Certificate.SignatureKey != nil {
	// 		key := ssh.MarshalAuthorizedKey(o.Certificate.SignatureKey)
	// 		if len(CAKey) < 3 {
	// 			CAKey = key
	// 		}
	// 		if !slices.Equal(key, CAKey) {
	// 			Log.Errorf("Certificate Authority key has changed from %#v to %#v", string(CAKey), string(key))
	// 			fmt.Fprintf(w, "\n\nCertificate Authority key has changed from \n%#v\nto \n%#v", string(CAKey), string(key))
	// 		}
	// 	}
	// 	fmt.Fprintf(w, "The SSH CA currently in use is: %s", CAKey)
	// 	Log.Printf("The SSH CA currently in use is:\n%s", CAKey)
	// }))

	// marshalUserinfo := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens, state string, rp rp.RelyingParty) {
	// 	w.Header().Add("location", successURI.String())
	// 	w.WriteHeader(301)
	// }

	// register the CodeExchangeHandler at the callbackPath
	// the CodeExchangeHandler handles the auth response, creates the token request and calls the callback function
	// with the returned tokens from the token endpoint
	return nil
}

type Provider struct {
	rp.RelyingParty
	providerURL   string
	clientID      string
	clientSecret  string
	scopes        []string
	redirectURI   url.URL
	cookieHandler *httphelper.CookieHandler
	updateDate    time.Time
	mut           sync.RWMutex
}

func (p *Provider) updateRP() {
	p.mut.RLock()
	if p.updateDate.After(time.Now()) && p.RelyingParty != nil {
		p.mut.RUnlock()
		return
	}
	p.mut.RUnlock()
	p.mut.Lock()
	defer p.mut.Unlock()
	options := []rp.Option{
		rp.WithCookieHandler(p.cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		rp.WithHTTPClient(sshrimp_http.Client),
	}
	options = append(options, rp.WithPKCE(p.cookieHandler))

	provider, err := rp.NewRelyingPartyOIDC(p.providerURL, p.clientID, p.clientSecret, p.redirectURI.String(), p.scopes, options...)
	if err != nil {
		Log.Printf("Failed to get oidc register oidc RelyingParty: %v", err)
		return
	}
	p.updateDate = time.Now().Add(time.Minute * 5)
	p.RelyingParty = provider
}

func (p *Provider) OAuthConfig() *oauth2.Config {
	p.updateRP()
	return p.RelyingParty.OAuthConfig()
}

func (p *Provider) Issuer() string {
	p.updateRP()
	return p.RelyingParty.Issuer()
}

func (p *Provider) IsPKCE() bool {
	p.updateRP()
	return p.RelyingParty.IsPKCE()
}

func (p *Provider) CookieHandler() *httphelper.CookieHandler {
	p.updateRP()
	return p.RelyingParty.CookieHandler()
}

func (p *Provider) HttpClient() *http.Client {
	p.updateRP()
	return p.RelyingParty.HttpClient()
}

func (p *Provider) IsOAuth2Only() bool {
	p.updateRP()
	return p.RelyingParty.IsOAuth2Only()
}

func (p *Provider) Signer() jose.Signer {
	p.updateRP()
	return p.RelyingParty.Signer()
}

func (p *Provider) UserinfoEndpoint() string {
	p.updateRP()
	return p.RelyingParty.UserinfoEndpoint()
}

func (p *Provider) GetEndSessionEndpoint() string {
	p.updateRP()
	return p.RelyingParty.GetEndSessionEndpoint()
}

func (p *Provider) IDTokenVerifier() rp.IDTokenVerifier {
	p.updateRP()
	return p.RelyingParty.IDTokenVerifier()
}

func (p *Provider) ErrorHandler() func(http.ResponseWriter, *http.Request, string, string, string) {
	p.updateRP()
	return p.RelyingParty.ErrorHandler()
}
