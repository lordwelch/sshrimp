package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"git.narnian.us/lordwelch/sshrimp/internal/config"
	"git.narnian.us/lordwelch/sshrimp/internal/signer"
	"git.narnian.us/lordwelch/sshrimp/internal/sshrimpagent"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	sigExit   = []os.Signal{os.Kill, os.Interrupt}
	sigIgnore = []os.Signal{}
	logger    = logrus.New()
	log       *logrus.Entry
)

var cli struct {
	Config string `kong:"arg,type='string',help='sshrimp config file (default: ${config_file} or ${env_var_name} environment variable)',default='${config_file}',env='SSHRIMP_CONFIG'"`
}

func main() {
	flag.StringVar(&cli.Config, "config", config.DefaultPath, "sshrimp config file")
	v := flag.Bool("v", false, "enable verbose logging")

	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	log = logger.WithFields(logrus.Fields{
		"pid": os.Getpid(),
	})
	sshrimpagent.Log = log
	signer.Log = log

	flag.Parse()

	if *v {
		logger.SetLevel(logrus.TraceLevel)
	}

	c := config.NewSSHrimpWithDefaults()
	err := c.Read(cli.Config)
	if err != nil {
		panic(err)
	}
	err = launchAgent(c)
	if err != nil {
		panic(err)
	}
}

func launchAgent(c *config.SSHrimp) error {
	var (
		err        error
		listener   net.Listener
		privateKey crypto.Signer
		signer     ssh.Signer
		logMessage string
	)

	log.Traceln("Creating socket")
	if _, err = os.Stat(c.Agent.Socket); err == nil {
		log.Tracef("File already exists at %s", c.Agent.Socket)
		conn, sockErr := net.Dial("unix", c.Agent.Socket)
		if conn == nil {
			logMessage = "conn is nil"
		}
		if sockErr == nil { // socket is accepting connections
			logMessage += "err reports successful connection"
			conn.Close()
			log.Errorf("Socket connected successfully %s", logMessage)
			return fmt.Errorf("socket %s already exists", c.Agent.Socket)
		}
		log.Tracef("Socket is not connected %s", logMessage)
		if os.Remove(c.Agent.Socket) == nil { // socket is not accepting connections, assuming safe to remove
			log.Traceln("Deleting socket: success")
		} else {
			log.Errorf("Deleting socket: fail")
		}
	}

	// This affects all files created for the process. Since this is a sensitive
	// socket, only allow the current user to write to the socket.
	syscall.Umask(0077)
	listener, err = net.Listen("unix", c.Agent.Socket)
	if err != nil {
		return err
	}
	defer listener.Close()

	fmt.Printf("listening on %s\n", c.Agent.Socket)

	// Generate a new SSH private/public key pair
	log.Tracef("Generating RSA %d ssh keys", 2048)
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	log.Traceln("Creating new signer from key")
	signer, err = ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return err
	}

	// Create the sshrimp agent with our configuration and the private key signer
	log.Traceln("Creating new sshrimp agent from signer and config")
	sshrimpAgent := sshrimpagent.NewSSHrimpAgent(c, signer)

	// Listen for signals so that we can close the listener and exit nicely
	log.Debugf("Ignoring signals: %v", sigIgnore)
	signal.Ignore(sigIgnore...)
	log.Debugf("Exiting on signals: %v", sigExit)
	osSignals := make(chan os.Signal)
	signal.Notify(osSignals, sigExit...)
	go func() {
		<-osSignals
		listener.Close()
	}()

	log.Traceln("Starting main loop")
	// Accept connections and serve the agent
	for {
		var conn net.Conn
		conn, err = listener.Accept()
		if err != nil {
			log.Errorf("Error accepting connection: %v", err)
			if strings.Contains(err.Error(), "use of closed network connection") {
				// Occurs if the user interrupts the agent with a ctrl-c signal
				return nil
			}
			return err
		}
		log.Traceln("Serving agent")
		if err = agent.ServeAgent(sshrimpAgent, conn); err != nil && !errors.Is(err, io.EOF) {
			log.Errorf("Error serving agent: %v", err)
			return err
		}
	}
}
