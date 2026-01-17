package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	logPath       = flag.String("log", "/var/log/null-logs/null-logs.log", "path to JSONL log file")
	url           = flag.String("url", "https://localhost:8443/ingest", "remote ingest URL (must be https)")
	cert          = flag.String("cert", "/etc/null-logs/forwarder.crt", "client certificate (PEM)")
	key           = flag.String("key", "/etc/null-logs/forwarder.key", "client key (PEM)")
	ca            = flag.String("ca", "/etc/null-logs/ca.crt", "CA bundle for server validation")
	batchSize     = flag.Int("batch", 50, "number of events per batch")
	flushInterval = flag.Duration("flush-interval", 5*time.Second, "max time to wait before sending a partial batch")
	bufferDir     = flag.String("buffer-dir", "/var/lib/null-logs/forwarder", "dir to store queued batches if remote unavailable")
)

func buildTransport() (*http.Transport, error) {
	certPEM, err := ioutil.ReadFile(*cert)
	if err != nil {
		return nil, err
	}
	keyPEM, err := ioutil.ReadFile(*key)
	if err != nil {
		return nil, err
	}
	certPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if caPEM, err := ioutil.ReadFile(*ca); err == nil {
		pool.AppendCertsFromPEM(caPEM)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{certPair},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
		// avoid insecure defaults
	}
	tr := &http.Transport{TLSClientConfig: tlsCfg}
	return tr, nil
}

func sendBatch(client *http.Client, batch []string) error {
	body := strings.Join(batch, "\n") + "\n"
	req, err := http.NewRequest("POST", *url, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := ioutil.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("bad status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func ensureDir(d string) error {
	return os.MkdirAll(d, 0700)
}

func main() {
	flag.Parse()
	tr, err := buildTransport()
	if err != nil {
		log.Fatalf("transport setup failed: %v", err)
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	if err := ensureDir(*bufferDir); err != nil {
		log.Fatalf("buffer dir: %v", err)
	}

	// tail the log file (simple, reopen on rotate)
	for {
		f, err := os.Open(*logPath)
		if err != nil {
			log.Printf("open log: %v, retrying in 2s", err)
			time.Sleep(2 * time.Second)
			continue
		}
		// seek to end
		f.Seek(0, io.SeekEnd)
		r := bufio.NewReader(f)
		batch := make([]string, 0, *batchSize)
		lastFlush := time.Now()
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					// flush if needed
					if len(batch) > 0 && time.Since(lastFlush) >= *flushInterval {
						if err := sendBatch(client, batch); err != nil {
							log.Printf("send failed: %v, writing to buffer", err)
							// write to buffer
							fname := filepath.Join(*bufferDir, fmt.Sprintf("%d.ndjson", time.Now().UnixNano()))
							ioutil.WriteFile(fname, []byte(strings.Join(batch, "\n")+"\n"), 0600)
						}
						batch = batch[:0]
						lastFlush = time.Now()
					}
					time.Sleep(200 * time.Millisecond)
					continue
				}
				// other errors -> break to reopen
				log.Printf("read error: %v", err)
				break
			}
			// append line (no error)
			batch = append(batch, strings.TrimRight(line, "\n"))
			if len(batch) >= *batchSize || time.Since(lastFlush) >= *flushInterval {
				if err := sendBatch(client, batch); err != nil {
					log.Printf("send failed: %v, writing to buffer", err)
					fname := filepath.Join(*bufferDir, fmt.Sprintf("%d.ndjson", time.Now().UnixNano()))
					ioutil.WriteFile(fname, []byte(strings.Join(batch, "\n")+"\n"), 0600)
				}
				batch = batch[:0]
				lastFlush = time.Now()
			}
		}
		f.Close()
		// small delay before reopening to handle rotation
		time.Sleep(500 * time.Millisecond)
	}
}
