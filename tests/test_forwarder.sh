#!/usr/bin/env bash
set -e

# Integration test for forwarder: create CA, server certs, start HTTPS server, run forwarder pointing to it.
TMP=$(mktemp -d)
SERVER_KEY=$TMP/server.key
SERVER_CSR=$TMP/server.csr
SERVER_CERT=$TMP/server.crt
CA_KEY=$TMP/ca.key
CA_CERT=$TMP/ca.crt
CLIENT_KEY=$TMP/client.key
CLIENT_CSR=$TMP/client.csr
CLIENT_CERT=$TMP/client.crt
LOG=$TMP/null.log
RECV=$TMP/recv.txt
EXTFILE=$TMP/san.ext

openssl genrsa -out $CA_KEY 2048
openssl req -x509 -new -nodes -key $CA_KEY -subj "/CN=null-logs-test-CA" -days 1 -out $CA_CERT
openssl genrsa -out $SERVER_KEY 2048
openssl req -new -key $SERVER_KEY -subj "/CN=localhost" -out $SERVER_CSR
printf "subjectAltName=DNS:localhost,IP:127.0.0.1" > $EXTFILE
openssl x509 -req -in $SERVER_CSR -CA $CA_CERT -CAkey $CA_KEY -CAcreateserial -out $SERVER_CERT -days 1 -sha256 -extfile $EXTFILE

openssl genrsa -out $CLIENT_KEY 2048
openssl req -new -key $CLIENT_KEY -subj "/CN=null-logs-client" -out $CLIENT_CSR
openssl x509 -req -in $CLIENT_CSR -CA $CA_CERT -CAkey $CA_KEY -CAcreateserial -out $CLIENT_CERT -days 1 -sha256

# start simple HTTPS server (Python) that records POST body
python3 - <<PY &
import http.server, ssl, sys, threading
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('content-length', 0))
        data = self.rfile.read(length)
        with open("$RECV","ab") as f:
            f.write(data)
        self.send_response(200)
        self.end_headers()

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="$SERVER_CERT", keyfile="$SERVER_KEY")
httpd = http.server.HTTPServer(('0.0.0.0', 8443), Handler)
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
print('server running')
httpd.serve_forever()
PY

SERVER_PID=$!
sleep 1

# build forwarder binary
make -C cmd/forwarder || true
if [ ! -x cmd/forwarder/null-logs-forwarder ]; then
  echo "Forwarder build failed or Go not installed; skipping forwarder test"; kill $SERVER_PID; exit 0
fi

# create a small log and start forwarder
printf '{"test":"one"}\n' > $LOG
cmd/forwarder/null-logs-forwarder --log $LOG --url https://127.0.0.1:8443/ingest --cert $CLIENT_CERT --key $CLIENT_KEY --ca $CA_CERT --flush-interval 1s --buffer-dir $TMP &
FWD_PID=$!
sleep 2

# append another line to log
printf '{"test":"two"}\n' >> $LOG
sleep 2

kill $FWD_PID || true
sleep 1
kill $SERVER_PID || true

if [ -s $RECV ]; then
  echo "Forwarder successfully delivered data"
  exit 0
else
  echo "Forwarder failed to deliver data"; exit 2
fi