# nats_to_syslog
Subscribes to NATs message bus and forwards messages to remote Syslog server

Example for use getting VM heartbeat messages from a Bosh director:
```bash
./nats_to_syslog \
        -nats-uri "tls://nats:somePassword@somehost:4222" \
        -nats-subject "hm.agent.heartbeat.>" \
        -syslog-endpoint "somesyslogendpoint:5000" \
        -mutualTLSCert ./nats_certificate \
        -mutualTLSKey ./nats_key \
        -noNatsMessagesToDebug \
        -extraFields "cf_foundation:sandbox" \
        -debug false
```

# Arguments

```bash
 ./nats_to_syslog  --help
Usage of ./nats_to_syslog:
  -debug
        debug logging true/false
  -extraFields string
        Extra fields to include in messages
  -mutualTLSCert string
        Path to cert for mutual TLS to NATS server
  -mutualTLSKey string
        Path to key for mutual TLS to NATS server
  -nats-subject string
        The NATS subject to subscribe to (default ">")
  -nats-uri string
        The NATS server URI (default "nats://localhost:4222")
  -noNatsMessagesToDebug
        Do not send NATS messages to debug (default true)
  -syslog-endpoint string
        The remote syslog server host:port (default "localhost:514")
```

# Testing

## Dependencies

```sh
go get github.com/onsi/ginkgo/ginkgo
go get github.com/nats-io/gnatsd

godep go test
```

# Build Instructions

- Ensure you have go 1.8.x installed
- To cross compile for linux on a mac:

```
cd nats_to_syslog/
GOOS=linux GOARCH=amd64 go build
```

- Omit the env vars if building on linux:

`cd nats_to_syslog/ && go build`
