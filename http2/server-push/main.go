package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
)

const indexHTML = `<html>
<head>
	<title>新世界杂货铺</title>
	<link rel="stylesheet" href="/static/style.css"">
</head>
<body>
	<div>Hello 新世界杂货铺</div>
	<div id="content"></div>
	<script src="/static/app.js"></script>
</body>
</html>
`

var httpAddr = flag.String("http", ":8080", "Listen address")

func main() {
	flag.Parse()
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		pusher, ok := w.(http.Pusher)
		if ok {
			// Push is supported. Try pushing rather than
			// waiting for the browser request these static assets.
			if err := pusher.Push("/static/app.js", nil); err != nil {
				log.Printf("Failed to push: %v", err)
			}
			if err := pusher.Push("/static/style.css", nil); err != nil {
				log.Printf("Failed to push: %v", err)
			}
		}
		fmt.Fprintf(w, indexHTML)
	})
	log.Fatal(http.ListenAndServeTLS(*httpAddr, "ca2.crt", "ca2.key", nil))
}
