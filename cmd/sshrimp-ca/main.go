package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"git.narnian.us/lordwelch/sshrimp/internal/config"
	"git.narnian.us/lordwelch/sshrimp/internal/signer"
	"github.com/BurntSushi/toml"
	"golang.org/x/crypto/ssh"
)

func httpError(w http.ResponseWriter, v interface{}, statusCode int) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	_ = e.Encode(v)
	http.Error(w, b.String(), statusCode)
}

type Server struct {
	config *config.SSHrimp
	Key    ssh.Signer
}

func NewServer(cfg *config.SSHrimp) (*Server, error) {
	server := &Server{
		config: cfg,
	}
	return server, nil
}

func (s *Server) LoadKey() error {
	b, err := os.ReadFile(s.config.CertificateAuthority.KeyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s.GenerateKey()
		}
		return err
	}
	s.Key, err = ssh.ParsePrivateKey(b)
	return err
}

func (s *Server) GenerateKey() error {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(s.config.CertificateAuthority.KeyPath, os.O_RDWR|os.O_CREATE, 0o400)
	if err == nil {
		defer file.Close()

		var pkcs8 []byte
		if pkcs8, err = x509.MarshalPKCS8PrivateKey(key); err == nil {
			err = pem.Encode(file, &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: pkcs8,
			})
		}
	}
	if err != nil {
		log.Printf("could not save generated CertificateAuthority key: %v", err)
	}
	s.Key, err = ssh.NewSignerFromKey(key)
	return err
}

// ServeHTTP handles a request to sign an SSH public key verified by an OpenIDConnect id_token
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if r.URL.Path == "/config" {
		io.Copy(io.Discard, r.Body)
		new_config := *s.config
		// new_config.CertificateAuthority
		w.Header().Add("Content-Type", "application/toml")
		t := toml.NewEncoder(w)
		_ = t.Encode(new_config)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		io.Copy(io.Discard, r.Body)
		w.Header().Add("Content-Type", "text/x-ssh-public-key")
		w.Write(ssh.MarshalAuthorizedKey(s.Key.PublicKey()))
		return
	}
	w.Header().Add("Content-Type", "application/json")
	// Load the configuration file, if not exsits, exit.
	var event signer.SSHrimpEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		httpError(w, signer.SSHrimpResult{Certificate: "", ErrorMessage: err.Error(), ErrorType: http.StatusText(http.StatusBadRequest)}, http.StatusBadRequest)
		return
	}

	certificate, err := signer.ValidateRequest(event, s.config, r.Header.Get("Function-Execution-Id"), fmt.Sprintf("%s/%s/%s", os.Getenv("GCP_PROJECT"), os.Getenv("FUNCTION_REGION"), os.Getenv("FUNCTION_NAME")))
	if err != nil {
		httpError(w, signer.SSHrimpResult{Certificate: "", ErrorMessage: err.Error(), ErrorType: http.StatusText(http.StatusBadRequest)}, http.StatusBadRequest)
		return
	}

	sshAlgorithmSigner, err := ssh.NewSignerWithAlgorithms(s.Key.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoED25519})
	if err != nil {
		httpError(w, signer.SSHrimpResult{Certificate: "", ErrorMessage: err.Error(), ErrorType: http.StatusText(http.StatusBadRequest)}, http.StatusBadRequest)
		return
	}

	// Sign the certificate!!
	if err := certificate.SignCert(rand.Reader, sshAlgorithmSigner); err != nil {
		httpError(w, signer.SSHrimpResult{Certificate: "", ErrorMessage: err.Error(), ErrorType: http.StatusText(http.StatusInternalServerError)}, http.StatusInternalServerError)
		return
	}

	// If you want to validate that the generated cert is correct
	// i, _ := identity.NewIdentity(s.config)
	// username, _ := i.Validate(event.Token)
	// cc := ssh.CertChecker{}
	// err = cc.CheckCert(username, &certificate)
	// if err != nil {
	// 	httpError(w, signer.SSHrimpResult{Certificate: "", ErrorMessage: err.Error(), ErrorType: http.StatusText(http.StatusInternalServerError)}, http.StatusBadRequest)
	// 	return
	// }

	// Return the certificate to the user
	pubkey, err := ssh.ParsePublicKey(certificate.Marshal())
	if err != nil {
		httpError(w, signer.SSHrimpResult{Certificate: "", ErrorMessage: err.Error(), ErrorType: http.StatusText(http.StatusInternalServerError)}, http.StatusInternalServerError)
		return
	}

	// Success!
	res := &signer.SSHrimpResult{
		Certificate:  string(ssh.MarshalAuthorizedKey(pubkey)),
		ErrorMessage: "",
		ErrorType:    "",
	}
	e := json.NewEncoder(w)
	_ = e.Encode(res)
}

func main() {
	cfgFile := flag.String("config", "/etc/sshrimp.toml", "Path to sshrimp.toml")
	addr := flag.String("addr", "127.0.0.1:8080", "Address to listen on")
	cfg := config.NewSSHrimp()
	if err := cfg.Read(*cfgFile); err != nil {
		log.Printf("Unable to read config file %s: %v", *cfgFile, err)
		os.Exit(1)
	}
	server, err := NewServer(cfg)
	if err != nil {
		log.Printf("Unable to start server: %v", err)
		os.Exit(2)
	}
	if err = http.ListenAndServe(*addr, server); err != nil {
		log.Printf("Error serving http: %v", err)
		os.Exit(99)
	}
}
