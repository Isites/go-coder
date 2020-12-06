package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		pusher, ok := w.(http.Pusher)
		if ok {
			// 主动推送服务资源
			if err := pusher.Push("/static/app.js", nil); err != nil {
				log.Printf("Failed to push: %v", err)
			}
			if err := pusher.Push("/static/style.css", nil); err != nil {
				log.Printf("Failed to push: %v", err)
			}
		}
		fmt.Fprintf(w, `<html>
		<head>
			<title>新世界杂货铺</title>
			<link rel="stylesheet" href="/static/style.css"">
		</head>
		<body>
			<div>Hello 新世界杂货铺</div>
			<div id="content"></div>
			<script src="/static/app.js"></script>
		</body>
		</html>`)
	})
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	// http.ListenAndServe(":8080", nil)
	// http.ListenAndServeTLS(":8080", "ca.crt", "ca.key", nil)
	server := &http.Server{Addr: ":8080", Handler: nil}
	server.TLSConfig = new(tls.Config)
	server.TLSConfig.PreferServerCipherSuites = true
	server.TLSConfig.NextProtos = append(server.TLSConfig.NextProtos, "h2", "http/1.1")
	server.TLSConfig.MaxVersion = tls.VersionTLS12
	server.ListenAndServeTLS("ca.crt", "ca.key")
}
