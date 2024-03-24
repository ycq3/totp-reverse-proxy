// main.go
package main

import (
	"flag"
	"log"
)

func main() {
	var listenKey, secretKey, upstreamURL string
	var certFile, keyFile, logDirectory string
	var useHTTPS bool
	flag.StringVar(&listenKey, "listen", ":9090", "Listen address")
	flag.StringVar(&secretKey, "secret", "", "TOTP Secret Key")
	flag.StringVar(&upstreamURL, "upstream", "", "Upstream URL")
	flag.BoolVar(&useHTTPS, "https", false, "Enable HTTPS")
	flag.StringVar(&certFile, "cert", "", "Path to HTTPS Certificate")
	flag.StringVar(&keyFile, "key", "", "Path to HTTPS key")
	flag.StringVar(&logDirectory, "logs", "", "Path to log directory")
	flag.Parse()

	if secretKey == "" || upstreamURL == "" {
		log.Println("Error: Secret key and upstream URL are required")
		flag.Usage()
	}

	proxy := NewTOTPReverseProxy(listenKey, secretKey, upstreamURL,
		useHTTPS, certFile, keyFile, logDirectory)
	if err := proxy.Start(); err != nil {
		log.Fatalf("Error starting TOTP reverse proxy: %v", err)
	}
}
