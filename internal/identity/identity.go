package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"unicode/utf8"

	"git.narnian.us/lordwelch/sshrimp/internal/config"
	"github.com/coreos/go-oidc/v3/oidc"
)

func init() {
	// Disable log prefixes such as the default timestamp.
	// Prefix text prevents the message from being parsed as JSON.
	// A timestamp is added when shipping logs to Cloud Logging.
	log.SetFlags(0)
}

// Entry defines a log entry.
type Entry struct {
	Message  string `json:"message"`
	Severity string `json:"severity,omitempty"`
	Trace    string `json:"logging.googleapis.com/trace,omitempty"`

	// Logs Explorer allows filtering and display of this as `jsonPayload.component`.
	Component string `json:"component,omitempty"`
}

// String renders an entry structure to the JSON format expected by Cloud Logging.
func (e Entry) String() string {
	if e.Severity == "" {
		e.Severity = "INFO"
	}
	out, err := json.Marshal(e)
	if err != nil {
		log.Printf("json.Marshal: %v", err)
	}
	return string(out)
}

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

		if len(claimedUsernames) == 0 {
			log.Println(Entry{
				Severity: "NOTICE",
				Message:  fmt.Sprintf("Did not find a username using: getClaim(%#v, %#v)", claim, claims),
			})
		}

		if idx < len(i.usernameREs) {
			for _, name := range claimedUsernames {
				usernames = append(usernames, parseUsername(name, i.usernameREs[idx]))
			}
		} else {
			usernames = append(usernames, claimedUsernames...)

		}
	}
	log.Println(Entry{
		Severity: "NOTICE",
		Message:  fmt.Sprintf("Adding usernames: %v", usernames),
	})
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
	return base64Decode(usernames)
}
func base64Decode(names []string) []string {
	for idx, name := range names {
		log.Println(Entry{
			Severity: "NOTICE",
			Message:  fmt.Sprintf("Attempting to decode %q as base64\n", name),
		})
		decoded, err := base64.RawURLEncoding.DecodeString(name)
		if err == nil && utf8.Valid(decoded) {
			names[idx] = string(decoded)
			log.Println(Entry{
				Severity: "NOTICE",
				Message:  fmt.Sprintf("Successfully decoded %q as base64\n", names[idx]),
			})
		}
	}
	return names
}
