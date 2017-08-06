package main

import (
	"log"
	"net/http"
	"flag"
	"crypto/tls"
	"fmt"
)

var certFile = flag.String("certFile", "server.crt", "the certificate file (e.g. openssl genrsa -out server.key 2048)")
var keyFile = flag.String("keyFile", "server.key", "the key file (e.g. openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650)")
var liveHost = flag.String("liveHost", "no", "the live host if using letsencrypt files (from /etc/letsencrypt/live/<domain>/)")

func main() {
	flag.Parse()

	if (*liveHost != "no") {
		*certFile = fmt.Sprintf("/etc/letsencrypt/live/%s/fullchain.pem", *liveHost)
		*keyFile = fmt.Sprintf("/etc/letsencrypt/live/%s/privkey.pem", *liveHost)
	}

	fmt.Println(*certFile, *keyFile);

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte("This is an example server.\n"))
	})
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, // h2
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256, // h2
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	srv := &http.Server{
		Addr:         ":443",
		Handler:      mux,
		TLSConfig:    cfg,
	}
	log.Fatal(srv.ListenAndServeTLS(*certFile, *keyFile))

}
