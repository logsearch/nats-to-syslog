package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"log/syslog"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"code.cloudfoundry.org/lager"
	"github.com/nats-io/nats"
)

type logEntry struct {
	Data    string
	Reply   string
	Subject string
}

var stop chan bool
var logger lager.Logger

func main() {
	logger = lager.NewLogger("nats_to_syslog")
	stop = make(chan bool)
	buffer := make(chan *nats.Msg, 1000)

	trapSignals()

	var natsURI = flag.String("nats-uri", "nats://localhost:4222", "The NATS server URI")
	var natsSubject = flag.String("nats-subject", ">", "The NATS subject to subscribe to")
	var syslogEndpoint = flag.String("syslog-endpoint", "localhost:514", "The remote syslog server host:port")
	var debug = flag.Bool("debug", false, "debug logging true/false")
	var mutualTLSKey = flag.String("mutualTLSKey", "", "Path to key for mutual TLS to NATS server")
	var mutualTLSCert = flag.String("mutualTLSCert", "", "Path to cert for mutual TLS to NATS server")
	var extraFields = flag.String("extraFields", "", "Extra fields to include in messages")

	// It appears that when debug is set false, the nats messages still go to stdout
	// Instead of further sleuthing, will do a workaround for now
	var noNatsMessagesToDebug = flag.Bool("noNatsMessagesToDebug", true, "Do not send NATS messages to debug")

	flag.Parse()

	// Handle any extra fields provided
	extraFieldCaptures := regexp.MustCompile("([^:,]+):([^:,]+)").FindAllStringSubmatch(*extraFields, -1)

	// Sanity check that mutual TLS key cert both set or not set
	if (*mutualTLSKey == "" && *mutualTLSCert != "") || (*mutualTLSKey != "" && *mutualTLSCert == "") {
		os.Stderr.WriteString("Usage error: mutualTLSKey and mutualTLSCert must be provided together\n")
		os.Exit(1)
	}

	setupLogger(*debug)

	syslog := connectToSyslog(*syslogEndpoint)
	defer syslog.Close()

	natsClient := connectToNATS(*natsURI, *mutualTLSKey, *mutualTLSCert)
	defer natsClient.Close()

	go func() {
		for message := range buffer {
			sendToSyslog(message, syslog, *noNatsMessagesToDebug, extraFieldCaptures)
		}
	}()

	_, err := natsClient.Subscribe(*natsSubject, func(message *nats.Msg) {
		buffer <- message
	})
	if err != nil {
		logger.Error("subscribed-to-subject-failed", err, lager.Data{"subject": *natsSubject})
	} else {
		logger.Info("subscribed-to-subject", lager.Data{"subject": *natsSubject})

		<-stop
	}
	logger.Info("bye.")
}

func handleError(err error, context string) {
	if err != nil {
		context = strings.Replace(context, " ", "-", -1)
		errorLogger := logger.Session(context)
		errorLogger.Error("error", err)
		os.Exit(1)
	}
}

func buildLogMessage(message *nats.Msg, extraFieldCaptures [][]string) string {

	// Add any extra fields
	var f interface{}
	err := json.Unmarshal(message.Data, &f)

	if err != nil {
		logger.Error("unmarshalling-message-data-failed", err, lager.Data{"data": string(message.Data)})
		return ""
	}

	m := f.(map[string]interface{})

	for _, match := range extraFieldCaptures {
		m[match[1]] = match[2]
	}

	messageDataModified, err := json.Marshal(m)
	if err != nil {
		logger.Error("unmarshalling-message-data-failed", err, lager.Data{"data": string(message.Data)})
		return ""
	}

	entry := logEntry{
		Data:    string(messageDataModified),
		Reply:   message.Reply,
		Subject: message.Subject,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		logger.Error("marshalling-log-failed", err, lager.Data{"data": string(message.Data)})
		return ""
	}

	return string(data)
}

func connectToSyslog(endpoint string) *syslog.Writer {
	syslog, err := syslog.Dial("tcp", endpoint, syslog.LOG_INFO, "nats_to_syslog")
	handleError(err, "connecting to syslog")
	logger.Info("connected-to-syslog", lager.Data{"endpoint": endpoint})
	return syslog
}

func connectToNATS(natsURI string, mutualTLSKey string, mutualTLSCert string) *nats.Conn {
	cert, err := tls.LoadX509KeyPair(mutualTLSCert, mutualTLSKey)
	handleError(err, "LoadX509KeyPair")

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Handle no mutual TLS key/cert please
	natsClient, err := nats.Connect(natsURI, nats.Secure(tlsConfig))
	handleError(err, "connecting to nats")
	logger.Info("connected-to-nats", lager.Data{"uri": natsURI})
	return natsClient
}

func sendToSyslog(message *nats.Msg, syslog *syslog.Writer, noNatsMessagesToDebug bool, extraFieldCaptures [][]string) {
	logMessage := buildLogMessage(message, extraFieldCaptures)
	if noNatsMessagesToDebug {
		logger.Debug("message-sent-to-syslog", lager.Data{"message": logMessage})
	}
	err := syslog.Info(logMessage)
	if err != nil {
		logger.Error("logging-to-syslog-failed", err)
		stop <- true
	}
}

func setupLogger(debug bool) {
	if debug {
		logger.RegisterSink(lager.NewWriterSink(os.Stdout, lager.DEBUG))
	} else {
		logger.RegisterSink(lager.NewWriterSink(os.Stdout, lager.INFO))
	}
}

func trapSignals() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT)
	signal.Notify(signals, syscall.SIGKILL)
	signal.Notify(signals, syscall.SIGTERM)

	go func() {
		for signal := range signals {
			logger.Info("signal-caught", lager.Data{"signal": signal})
			stop <- true
		}
	}()
}
