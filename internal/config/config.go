package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Agent config for the sshrimp-agent agent
type Agent struct {
	ProviderURL  string
	ClientID     string
	ClientSecret string
	Socket       string
	Scopes       []string
	KeyPath      string
	Port         int
	CAUrls       []string
}

// CertificateAuthority config for the sshrimp-ca lambda
type CertificateAuthority struct {
	KeyPath            string
	ForceCommandRegex  string
	SourceAddressRegex string
	UsernameRegexs     []string
	UsernameClaims     []string
	ValidAfterOffset   string
	ValidBeforeOffset  string
	Extensions         []string
}

// SSHrimp main configuration struct for sshrimp-agent and sshrimp-ca
type SSHrimp struct {
	Agent                Agent
	CertificateAuthority CertificateAuthority
}

var supportedExtensions = []string{
	"no-agent-forwarding",
	"no-port-forwarding",
	"no-pty",
	"no-user-rc",
	"no-x11-forwarding",
	"permit-agent-forwarding",
	"permit-port-forwarding",
	"permit-pty",
	"permit-user-rc",
	"permit-x11-forwarding",
}

// NewSSHrimp returns SSHrimp
func NewSSHrimp() *SSHrimp {
	return &SSHrimp{}
}

// NewSSHrimpWithDefaults returns SSHrimp with defaults already set
func NewSSHrimpWithDefaults() *SSHrimp {
	sshrimp := SSHrimp{
		Agent{
			ProviderURL: "https://accounts.google.com",
			Socket:      "~/.ssh/sshrimp.sock",
			Scopes:      []string{"openid", "email", "profile"},
		},
		CertificateAuthority{
			ForceCommandRegex:  "^$",
			SourceAddressRegex: "^$",
			UsernameRegexs:     []string{`^(.*)@example\.com$`},
			UsernameClaims:     []string{"email"},
			ValidAfterOffset:   "-5m",
			ValidBeforeOffset:  "+12h",
			Extensions: []string{
				"permit-agent-forwarding",
				"permit-port-forwarding",
				"permit-pty",
				"permit-user-rc",
				"no-x11-forwarding",
			},
		},
	}
	return &sshrimp
}

func validateInt(val interface{}) error {
	if str, ok := val.(string); ok {
		if _, err := strconv.Atoi(str); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("expected type string got %v", reflect.TypeOf(val).Name())
	}

	return nil
}

func validateURL(val interface{}) error {
	if str, ok := val.(string); ok {
		if _, err := url.ParseRequestURI(str); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("expected type string got %v", reflect.TypeOf(val).Name())
	}

	return nil
}

func validateDuration(val interface{}) error {
	if str, ok := val.(string); ok {
		if _, err := time.ParseDuration(str); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("expected type string got %v", reflect.TypeOf(val).Name())
	}

	return nil
}

func validateAlias(val interface{}) error {
	if str, ok := val.(string); ok {
		if !strings.HasPrefix(str, "alias/") {
			return errors.New("KMS alias must begin with alias/")
		}
	} else {
		return fmt.Errorf("expected type string got %v", reflect.TypeOf(val).Name())
	}

	return nil
}

func (c *SSHrimp) Read(configPath string) error {
	_, err := toml.DecodeFile(configPath, c)
	return err
}

func (c *SSHrimp) Write(configPath string) error {
	// Create the new config file
	configFile, err := os.Create(configPath)
	if err != nil {
		return err
	}
	defer configFile.Close()

	// Encode the configuration values as a TOML file
	encoder := toml.NewEncoder(configFile)
	if err := encoder.Encode(c); err != nil {
		return err
	}

	return nil
}
