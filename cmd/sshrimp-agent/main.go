package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"gitea.narnian.us/lordwelch/sshrimp/internal/config"
	"gitea.narnian.us/lordwelch/sshrimp/internal/signer"
	"gitea.narnian.us/lordwelch/sshrimp/internal/sshrimpagent"
	"github.com/prometheus/procfs"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"inet.af/peercred"
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
	Foreground   bool
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
	err := os.MkdirAll(config.LogDirectory, 0o750)
	if err != nil {
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
	logger.Out = io.Discard
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

func main2(cli cfg, c *config.SSHrimp) {
	listener := openSocket(ExpandPath(c.Agent.Socket))
	if listener == nil {
		log.Errorln("Failed to open socket")
		return
	}
	err := setupLoging(cli)
	if err != nil {
		log.Warnf("Error setting up logging: %v", err)
	}
	err = launchAgent(c, listener)
	if err != nil {
		log.Panic("Failed to launch agent", err)
	}
}

func main() {
	defaultConfigPath := "~/.ssh/sshrimp.toml"
	if configPathFromEnv, ok := os.LookupEnv("SSHRIMP_CONFIG"); ok && configPathFromEnv != "" {
		defaultConfigPath = configPathFromEnv
	}
	var (
		cli cfg
		err error
	)
	flag.StringVar(&cli.Config, "config", defaultConfigPath, "sshrimp config file")
	flag.StringVar(&cli.LogDirectory, "log", getLogDir(), "sshrimp log directory")
	flag.BoolVar(&cli.Verbose, "v", false, "enable verbose logging")
	flag.BoolVar(&cli.Foreground, "f", false, "Run in the foreground")

	flag.Parse()
	sshCommand := flag.Args()
	if cli.Verbose {
		logger.SetLevel(logrus.DebugLevel)
	}

	cfgFile := ExpandPath(cli.Config)
	cfgFile, err = filepath.Abs(cfgFile)
	if err != nil {
		log.Errorln("config must be an absolute path")
		os.Exit(1)
	}
	c := config.NewSSHrimpWithDefaults()
	err = c.Read(cfgFile)
	if err != nil {
		panic(err)
	}
	if os.Getenv("SSHRIMP_DAEMON") == "true" {
		cli.Foreground = true
	}
	if cli.Foreground {
		logger.Println("Launching agent")
		main2(cli, c)
	} else {
		logger.Debug("Attempting to start daemon")
		var nullFile *os.File
		nullFile, err = os.Open(os.DevNull)
		if err != nil {
			panic(err)
		}
		env := os.Environ()
		env = append(env, "SSHRIMP_DAEMON=true")
		executable, err := os.Executable()
		if err != nil {
			panic(err)
		}
		_, err = os.StartProcess(executable, os.Args, &os.ProcAttr{
			Dir:   filepath.Dir(cfgFile),
			Env:   env,
			Files: []*os.File{nullFile, nullFile, nullFile},
			Sys: &syscall.SysProcAttr{
				// Chroot:     d.Chroot,
				Setsid: true,
			},
		})
		if err != nil {
			panic(err)
		}
		nullFile.Close()
		logger.Debugf("Agent started in the background check %s for logs", getLogDir())
	}
	if len(sshCommand) > 1 && filepath.Base(sshCommand[0]) == "ssh" {
		syscall.Exec(sshCommand[0], sshCommand, os.Environ())
	}
}

func socketWorks(path string) bool {
	var (
		pid  int
		cred *peercred.Creds
	)
	conn, sockErr := net.Dial("unix", path)
	if sockErr != nil {
		return false
	}
	if conn == nil {
		return false
	}
	defer conn.Close()

	cred, sockErr = peercred.Get(conn)
	if sockErr != nil {
		return false
	}

	var (
		ok      bool
		process *os.Process
	)
	pid, ok = cred.PID()
	if !ok {
		return false
	}
	process, sockErr = os.FindProcess(pid)
	if sockErr != nil {
		return false
	}
	defer process.Release()
	return process.Signal(syscall.SIGHUP) == nil
}

func openSocket(socketPath string) net.Listener {
	var (
		listener   net.Listener
		err        error
		logMessage string
	)

	if socketWorks(socketPath) { // socket is accepting connections
		log.Printf("socket %s already exists\n", socketPath)
		return nil
	}
	log.Printf("Socket is not connected %s\n", logMessage)
	err = os.Remove(socketPath)
	if err == nil { // socket is not accepting connections, assuming safe to remove
		log.Println("Deleting socket: success")
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Println("Deleting socket: fail", err)
		return nil
	}

	// This affects all files created for the process. Since this is a sensitive
	// socket, only allow the current user to write to the socket.
	syscall.Umask(0o077)
	listener, err = net.Listen("unix", socketPath)
	if err != nil {
		log.Println("Error opening socket:", err)
		return nil
	}
	log.Println("Opened socket", socketPath)
	return listener
}

func getConnectedProcess(conn net.Conn) string {
	var (
		cred *peercred.Creds
		err  error
	)
	cred, err = peercred.Get(conn)
	if err != nil {
		return ""
	}
	pid, ok := cred.PID()
	if !ok {
		return ""
	}
	var (
		proc procfs.Proc
		name string
	)
	proc, err = procfs.NewProc(pid)
	if err != nil {
		return fmt.Sprintf("pid %d", pid)
	}
	name, err = proc.Executable()
	if err == nil {
		return fmt.Sprintf("pid %d", pid)
	}
	return name
}

func handle(sshrimpAgent agent.Agent, conn net.Conn) (err error) {
	defer func() {
		panicErr := recover()

		if panicErr != nil {
			if err != nil {
				err = fmt.Errorf("something panicked: %w: %v", err, panicErr)
				return
			}
			err, _ = panicErr.(error)
			return
		}
	}()
	log.Infof("Serving agent to %s", getConnectedProcess(conn))
	if err = agent.ServeAgent(sshrimpAgent, conn); err != nil && !errors.Is(err, io.EOF) {
		log.Errorf("Error serving agent: %v", err)
		return err
	}
	return err
}

func launchAgent(c *config.SSHrimp, listener net.Listener) error {
	var (
		err        error
		privateKey crypto.Signer
		sshSigner  ssh.Signer
	)
	defer listener.Close()

	log.Printf("listening on %s\n", c.Agent.Socket)

	// Generate a new SSH private/public key pair
	log.Tracef("Generating ed25519 ssh keys")
	_, privateKey, err = ed25519.GenerateKey(rand.Reader)
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
		log.Errorf("Failed to create sshrimpAgent: %v", err)
	}

	// Listen for signals so that we can close the listener and exit nicely
	log.Debugf("Ignoring signals: %v", sigIgnore)
	signal.Ignore(sigIgnore...)
	log.Debugf("Exiting on signals: %v", sigExit)
	osSignals := make(chan os.Signal, 10)
	signal.Notify(osSignals, sigExit...)
	go func() {
		sig := <-osSignals
		log.Infof("Recieved signal %v: closing", sig)
		os.Exit(0)
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
				continue
			}
			log.Errorf("Error accepting connection: %v", err)
		}
		go handle(sshrimpAgent, conn)
	}
}
