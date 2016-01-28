package main

import (
	"flag"
	"gdata"
	"log"
	"net/http"
)

var fPort = flag.String("listen", ":12311", "Address to listen on")

func main() {
	flag.Parse()

	server, err := gdata.NewServer()
	if err != nil {
		log.Fatal(err)
	}

	http.ListenAndServe(*fPort, server)
}
