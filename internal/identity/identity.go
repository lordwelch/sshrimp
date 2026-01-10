package identity

import (
	"context"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"gitea.narnian.us/lordwelch/sshrimp/internal/config"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sirupsen/logrus"
)

// Identity holds information required to verify an OIDC identity token
type Identity struct {
	ctx            context.Context
	verifier       *oidc.IDTokenVerifier
	usernameREs    []*regexp.Regexp
	usernameClaims []string
	log            *logrus.Entry
}

// NewIdentity return a new Identity, with default values and oidc proivder information populated
func NewIdentity(log *logrus.Entry, c *config.SSHrimp) (*Identity, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, c.Agent.ProviderURL)
	if err != nil {
		return nil, err
	}

	oidcConfig := &oidc.Config{
		ClientID:             c.Agent.ClientID,
		SupportedSigningAlgs: []string{"RS256"},
	}

	regexes := make([]*regexp.Regexp, 0, len(c.CertificateAuthority.UsernameRegexs))
	for _, regex := range c.CertificateAuthority.UsernameRegexs {
		regexes = append(regexes, regexp.MustCompile(regex))
	}

	return &Identity{
		ctx:            ctx,
		verifier:       provider.Verifier(oidcConfig),
		usernameREs:    regexes,
		usernameClaims: c.CertificateAuthority.UsernameClaims,
		log:            log,
	}, nil
}

// Validate an identity token
func (i *Identity) Validate(token string) ([]string, error) {

	idToken, err := i.verifier.Verify(i.ctx, token)
	if err != nil {
		return nil, errors.New("failed to verify identity token: " + err.Error())
	}
	return i.getUsernames(idToken)
}

func (i *Identity) getUsernames(idToken *oidc.IDToken) ([]string, error) {
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, errors.New("failed to parse claims: " + err.Error())
	}
	usernames := make([]string, 0, len(i.usernameClaims))
	for idx, claim := range i.usernameClaims {

		claimedUsernames := i.getClaim(claim, claims)

		if len(claimedUsernames) == 0 {
			i.log.Errorf("Did not find a username using: getClaim(%#v, %#v)", claim, claims)
		}

		if idx < len(i.usernameREs) {
			for _, name := range claimedUsernames {
				usernames = append(usernames, parseUsername(name, i.usernameREs[idx]))
			}
		} else {
			usernames = append(usernames, claimedUsernames...)

		}
	}
	i.log.Infof("Adding usernames: %v", usernames)
	if len(usernames) < 1 {
		return nil, errors.New("configured username claim not in identity token")
	}
	return usernames, nil
}

func parseUsername(username string, re *regexp.Regexp) string {
	if match := re.FindStringSubmatch(username); match != nil {
		return match[1]
	}
	return ""
}

func (i *Identity) getClaim(claim string, claims map[string]interface{}) []string {
	usernames := make([]string, 0, 2)
	parts := strings.Split(claim, ".")
f:
	for idx, part := range parts {
		switch v := claims[part].(type) {
		case map[string]interface{}:
			claims = v
		case []map[string]string:
			for _, claimItem := range v {
				name, ok := claimItem[parts[idx+1]]
				if ok {
					usernames = append(usernames, name)
				}
			}
			break f
		case []interface{}:
			for _, value := range v {
				if name, ok := value.(string); ok {
					usernames = append(usernames, name)
				}
			}
			break f
		case string:
			usernames = append(usernames, v)
		default:
			break f
		}

	}
	return i.base64Decode(usernames)
}
func (i *Identity) base64Decode(names []string) []string {
	for idx, name := range names {
		i.log.Debugf("Attempting to decode %q as base64\n", name)
		decoded, err := base64.RawURLEncoding.DecodeString(name)
		if err == nil && utf8.Valid(decoded) {
			names[idx] = string(decoded)
			i.log.Debugf("Successfully decoded %q as base64\n", names[idx])
		}
	}
	return names
}
