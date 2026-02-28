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
	pkce     string
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
	}
	redirectURI.Path = "/auth/callback"
	client := &OidcClient{
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
