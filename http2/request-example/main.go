package main

import (
	"net/http"
	"time"
)

func main() {
	http.Get("https://dss0.bdstatic.com/5aV1bjqh_Q23odCf/static/superman/img/topnav/baiduyun@2x-e0be79e69e.png")
	time.Sleep(time.Second * 3)
}
