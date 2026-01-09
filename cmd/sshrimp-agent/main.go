package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"git.narnian.us/lordwelch/sshrimp/internal/config"
	"git.narnian.us/lordwelch/sshrimp/internal/signer"
	"git.narnian.us/lordwelch/sshrimp/internal/sshrimpagent"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	sigExit   = []os.Signal{os.Kill, os.Interrupt}
	sigIgnore []os.Signal
	logger    = logrus.New()
	log       *logrus.Entry
	appname   = "sshrimp"
)

type cfg struct {
	Config       string
	LogDirectory string
	Verbose      bool
}

func getLogDir() string {
	logdir := ""

	switch runtime.GOOS {
	case "plan9":
		if dir, err := os.UserConfigDir(); err == nil {
			logdir = filepath.Join(dir, "logs", appname)
		}
	case "darwin", "ios":
		if dir, err := os.UserHomeDir(); err == nil {
			logdir = filepath.Join(dir, "Library/Logs", appname)
		}
	default:
		if dir, err := os.UserCacheDir(); err == nil {
			logdir = filepath.Join(dir, appname, "logs")
		}
	}
	if logdir == "" {
		if dir, err := os.UserHomeDir(); err == nil {
			logdir = filepath.Join(dir, ".ssh/sshrimp_logs")
		}
	}
	return logdir
}

func setupLoging(config cfg) error {
	levels := []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
	}
	err := os.MkdirAll(config.LogDirectory, 0750)
	if err != nil && !os.IsExist(err) {
		log.Fatal(err)
	}

	logName := filepath.Join(config.LogDirectory, appname+".log")
	logRotate(logName, 10)
	logger.SetLevel(logrus.TraceLevel)
	if config.Verbose {
		levels = logrus.AllLevels
	}

	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	logger.AddHook(&writer.Hook{ // Send logs with level higher than warning to stderr
		Writer:    os.Stderr,
		LogLevels: levels,
	})
	logger.Out = ioutil.Discard
	file, err := os.Create(logName)
	if err != nil {
		return err
	}
	// defer file.Close()
	logger.AddHook(&writer.Hook{ // Send all logs to file
		Writer:    file,
		LogLevels: logrus.AllLevels,
	})
	log = logger.WithFields(logrus.Fields{
		"pid": os.Getpid(),
	})

	sshrimpagent.Log = log
	signer.Log = log
	return nil
}

func ExpandPath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}

	if path[0] == '~' {
		path = filepath.Join(home, path[1:])
	}
	return path
}

func main() {
	defaultConfigPath := "~/.ssh/sshrimp.toml"
	if configPathFromEnv, ok := os.LookupEnv("SSHRIMP_CONFIG"); ok && configPathFromEnv != "" {
		defaultConfigPath = configPathFromEnv
	}
	var cli cfg
	flag.StringVar(&cli.Config, "config", defaultConfigPath, "sshrimp config file")
	flag.StringVar(&cli.LogDirectory, "log", getLogDir(), "sshrimp log directory")
	flag.BoolVar(&cli.Verbose, "v", false, "enable verbose logging")
	fmt.Println(getLogDir())

	flag.Parse()

	c := config.NewSSHrimpWithDefaults()
	err := c.Read(ExpandPath(cli.Config))
	if err != nil {
		panic(err)
	}
	listener := openSocket(ExpandPath(c.Agent.Socket))
	if listener == nil {
		logger.Errorln("Failed to open socket")
		return
	}
	if err := setupLoging(cli); err != nil {
		logger.Warnf("Error setting up logging: %v", err)
	}
	err = launchAgent(c, listener)
	if err != nil {
		panic(err)
	}
}

func openSocket(socketPath string) net.Listener {
	var (
		listener   net.Listener
		err        error
		logMessage string
	)

	if _, err = os.Stat(socketPath); err == nil {
		fmt.Println("Creating socket")
		fmt.Printf("File already exists at %s\n", socketPath)
		conn, sockErr := net.Dial("unix", socketPath)
		if conn == nil {
			logMessage = "conn is nil"
		}
		if sockErr == nil { // socket is accepting connections
			conn.Close()
			fmt.Printf("socket %s already exists\n", socketPath)
			return nil
		}
		fmt.Printf("Socket is not connected %s\n", logMessage)
		err = os.Remove(socketPath)
		if err == nil { // socket is not accepting connections, assuming safe to remove
			fmt.Println("Deleting socket: success")
		} else {
			fmt.Println("Deleting socket: fail", err)
			return nil
		}
	}

	// This affects all files created for the process. Since this is a sensitive
	// socket, only allow the current user to write to the socket.
	syscall.Umask(0o077)
	listener, err = net.Listen("unix", socketPath)
	if err != nil {
		fmt.Println("Error opening socket:", err)
		return nil
	}
	return listener
}

func launchAgent(c *config.SSHrimp, listener net.Listener) error {
	var (
		err        error
		privateKey crypto.Signer
		sshSigner  ssh.Signer
	)
	defer listener.Close()

	fmt.Printf("listening on %s\n", c.Agent.Socket)

	// Generate a new SSH private/public key pair
	log.Tracef("Generating RSA %d ssh keys", 2048)
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	log.Traceln("Creating new sshSigner from key")
	sshSigner, err = ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return err
	}

	// Create the sshrimp agent with our configuration and the private key sshSigner
	log.Traceln("Creating new sshrimp agent from sshSigner and config")
	sshrimpAgent, err := sshrimpagent.NewSSHrimpAgent(c, sshSigner)
	if err != nil {
		log.Logger.Errorf("Failed to create sshrimpAgent: %v", err)
	}

	// Listen for signals so that we can close the listener and exit nicely
	log.Debugf("Ignoring signals: %v", sigIgnore)
	signal.Ignore(sigIgnore...)
	log.Debugf("Exiting on signals: %v", sigExit)
	osSignals := make(chan os.Signal, 10)
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
