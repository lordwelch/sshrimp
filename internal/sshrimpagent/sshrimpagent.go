package sshrimpagent

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"gitea.narnian.us/lordwelch/sshrimp/internal/config"
	"gitea.narnian.us/lordwelch/sshrimp/internal/signer"
	"github.com/google/uuid"
	"github.com/pkg/browser"
	"github.com/rymdport/portal/openuri"
	"github.com/sirupsen/logrus"
	"github.com/zitadel/oidc/pkg/client"
	"github.com/zitadel/oidc/pkg/client/rp"
	"github.com/zitadel/oidc/pkg/oidc"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var Log *logrus.Entry

type sshrimpAgent struct {
	oidcClient  *OidcClient
	signer      ssh.Signer
	certificate *ssh.Certificate
	token       *oidc.Tokens
	config      *config.SSHrimp
}

// NewSSHrimpAgent returns an agent.Agent capable of signing certificates with a SSHrimp Certificate Authority
func NewSSHrimpAgent(c *config.SSHrimp, signer ssh.Signer) (agent.Agent, error) {
	oidcClient, err := newOIDCClient(c)
	if err != nil {
		return nil, err
	}

	return &sshrimpAgent{
		oidcClient:  oidcClient,
		signer:      signer,
		certificate: &ssh.Certificate{},
		token:       nil,
		config:      c,
	}, nil
}

// authenticate authenticates a oidc token
func (r *sshrimpAgent) authenticate() error {
	var err error
	if r.token != nil {
		err = oidc.CheckExpiration(r.token.IDTokenClaims, 0)
	} else {
		err = errors.New("no token provided")
	}
	if err != nil {
		// Log.Debugln("Token is expired re-authenticating http://" + r.oidcClient.Addr + "/login")
		// OpenURL("http://" + r.oidcClient.Addr + "/login")
		r.startAuth()
		select {
		case r.token = <-r.oidcClient.OIDCToken:
			return nil
		case <-time.After(30 * time.Second):
			return errors.New("Timeout")
		}
	}
	return err
}

func OpenURL(url string) {
	if openuri.OpenURI("", url, nil) == nil {
		return
	}
	_ = browser.OpenURL(url)
}

func (r *sshrimpAgent) startAuth() {
	r.oidcClient.pkce = base64.RawURLEncoding.EncodeToString([]byte(uuid.New().String()))
	codeChallenge := oidc.NewSHACodeChallenge(r.oidcClient.pkce)
	log.Println("pkce", r.oidcClient.pkce, codeChallenge)
	c := r.oidcClient.provider.OAuthConfig()
	uri, _ := url.Parse(c.Endpoint.AuthURL)
	v := uri.Query()
	v.Set("code_challenge", codeChallenge)
	v.Set("code_challenge_method", "S256")
	v.Set("response_type", "code")
	v.Set("client_id", c.ClientID)
	if c.RedirectURL != "" {
		v.Set("redirect_uri", c.RedirectURL)
	}
	if len(c.Scopes) > 0 {
		v.Set("scope", strings.Join(c.Scopes, " "))
	}

	uri.RawQuery = v.Encode()
	OpenURL(uri.String())
}

// RemoveAll clears the current certificate and identity token (including refresh token)
func (r *sshrimpAgent) RemoveAll() error {
	Log.Debugln("Removing identity token and certificate")
	r.certificate = &ssh.Certificate{}
	r.oidcClient.Certificate = r.certificate
	r.token = nil
	return nil
}

// Remove has the same functionality as RemoveAll
func (r *sshrimpAgent) Remove(key ssh.PublicKey) error {
	return r.RemoveAll()
}

// Lock is not supported on this agent
func (r *sshrimpAgent) Lock(passphrase []byte) error {
	return errors.New("sshrimp-agent: locking not supported")
}

// Unlock is not supported on this agent
func (r *sshrimpAgent) Unlock(passphrase []byte) error {
	return errors.New("sshrimp-agent: unlocking not supported")
}

// List returns the identities, but also signs the certificate using sshrimp-ca if expired.
func (r *sshrimpAgent) List() ([]*agent.Key, error) {
	Log.Traceln("Listing current identities")
	validEndDate := time.Unix(int64(r.certificate.ValidBefore), 0)

	if r.certificate.ValidBefore != uint64(ssh.CertTimeInfinity) && (time.Now().After(validEndDate) || validEndDate.Unix() < 0) {
		Log.Traceln("Certificate has expired")
		Log.Traceln("authenticating token")
		err := r.authenticate()
		if err != nil {
			Log.Errorf("authenticating the token failed: %v", err)
			return nil, err
		}

		Log.Traceln("signing certificate")
		cert, err := signer.SignCertificateAllURLs(r.signer.PublicKey(), r.token.IDToken, "", r.config.Agent.CAUrls)
		if err != nil {
			Log.Errorf("signing certificate failed: %v", err)
			return nil, err
		}
		r.certificate = cert
		r.oidcClient.Certificate = r.certificate
	}

	var ids []*agent.Key
	ids = append(ids, &agent.Key{
		Format:  r.certificate.Type(),
		Blob:    r.certificate.Marshal(),
		Comment: r.certificate.KeyId,
	})
	return ids, nil
}

// Add is not supported on this agent. For multiple OIDC backends, run multiple agents.
func (r *sshrimpAgent) Add(key agent.AddedKey) error {
	return errors.New("sshrimp-agent: adding identities not supported")
}

// Sign uses our private key to sign the challenge required to authenticate to the ssh host.
func (r *sshrimpAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return r.signer.Sign(rand.Reader, data)
}

// Signers list our current signers which there is only one.
func (r *sshrimpAgent) Signers() ([]ssh.Signer, error) {
	return []ssh.Signer{
		r.signer,
	}, nil
}

func (r *sshrimpAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	Log.Traceln("requested sign with flags")
	sign, ok := r.signer.(ssh.AlgorithmSigner)
	Log.Tracef("signer is AlgorithmSigner: %v", ok)
	if ok {
		if flags&agent.SignatureFlagRsaSha512 == agent.SignatureFlagRsaSha512 {
			Log.Traceln("sha 512 requested")
			s, err := sign.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoRSASHA512)
			if err == nil {
				Log.Debugln("sha 512 available")
				return s, nil
			}
		}
		if flags&agent.SignatureFlagRsaSha256 == agent.SignatureFlagRsaSha256 {
			Log.Traceln("sha 256 requested")
			s, err := sign.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoRSASHA256)
			if err == nil {
				Log.Debugln("sha 256 available")
				return s, nil
			}
		}
	}
	Log.Traceln("signing data")
	return r.Sign(key, data)
}

func (r *sshrimpAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType == "sshrimp-oauth" {
		URL, err := url.Parse(string(contents))
		log.Printf("%#v", URL)
		if err != nil {
			return fmt.Appendf(nil, "Failed to parse url: %v", err), nil
		}
		params := URL.Query()
		if params.Get("error") != "" {
			return fmt.Appendf(nil, "Failed to authenticate: %v", params.Get("error_description")), nil
		}
		codeOpts := []rp.CodeExchangeOpt{
			rp.WithCodeVerifier(r.oidcClient.pkce),
		}

		if r.oidcClient.provider.Signer() == nil {
			assertion, err := client.SignedJWTProfileAssertion(r.config.Agent.ClientID, []string{r.oidcClient.provider.Issuer()}, time.Hour, r.oidcClient.provider.Signer())
			if err != nil {
				log.Printf("failed to build assertion: %v", err)
				return fmt.Appendf(nil, "failed to build assertion: %v", err), nil
			}
			codeOpts = append(codeOpts, rp.WithClientAssertionJWT(assertion))
		}
		ctx := context.Background()
		tokens, err := rp.CodeExchange(ctx, params.Get("code"), r.oidcClient.provider, codeOpts...)
		if err != nil {
			log.Printf("failed to exchange token: %v", err)
			return fmt.Appendf(nil, "failed to exchange token: %v", err), nil
		}
		r.oidcClient.OIDCToken <- tokens
		return contents, nil
	}
	return nil, agent.ErrExtensionUnsupported
}
