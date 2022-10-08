package identity

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"git.narnian.us/lordwelch/sshrimp/internal/config"
	"github.com/coreos/go-oidc/v3/oidc"
)

// Identity holds information required to verify an OIDC identity token
type Identity struct {
	ctx            context.Context
	verifier       *oidc.IDTokenVerifier
	usernameREs    []*regexp.Regexp
	usernameClaims []string
}

// NewIdentity return a new Identity, with default values and oidc proivder information populated
func NewIdentity(c *config.SSHrimp) (*Identity, error) {
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

		claimedUsernames := getClaim(claim, claims)

		if idx < len(i.usernameREs) {
			for _, name := range claimedUsernames {
				usernames = append(usernames, parseUsername(name, i.usernameREs[idx]))
			}
		} else {
			usernames = append(usernames, claimedUsernames...)
		}
	}
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

func getClaim(claim string, claims map[string]interface{}) []string {
	usernames := make([]string, 0, 2)
	parts := strings.Split(claim, ".")
f:
	for idx, part := range parts {
		if idx == len(parts)-1 {
			name, ok := claims[part].(string)
			if ok {
				usernames = append(usernames, name)
			}
			return usernames
		}

		fmt.Println(part)
		switch v := claims[part].(type) {
		case map[string]interface{}:
			claims = v
		case []map[string]string:
			fmt.Println("fuck zitadel")
			for _, claimItem := range v {
				name, ok := claimItem[parts[idx+1]]
				if ok {
					usernames = append(usernames, name)
				}
			}
			break f
		default:
			break f
		}

	}
	return base64Decode(usernames)
}
func base64Decode(names []string) []string {
	for idx, name := range names {
		decoded, err := base64.StdEncoding.Strict().DecodeString(name)
		if err == nil && utf8.Valid(decoded) {
			names[idx] = string(decoded)
		}
	}
	return names
}
