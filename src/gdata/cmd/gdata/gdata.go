package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"gdata"
	"log"
	"net/http"
	"os"
)

var (
	fPort    = flag.String("listen", ":12311", "Address to listen on")
	fMakeKey = flag.String("make-key", "", "Create a new key to sign JWTs with")
	fKey     = flag.String("key", "", "Private key to create JWTs with")
)

func main() {
	flag.Parse()

	if *fMakeKey != "" {
		f, err := os.Create(*fMakeKey)
		if err != nil {
			log.Fatal(err)
		}

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}

		data, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			log.Fatal(err)
		}

		var blk pem.Block

		blk.Bytes = data
		blk.Type = "ecdsa-key"

		err = pem.Encode(f, &blk)
		if err != nil {
			log.Fatal(err)
		}

		f.Close()

		return
	}

	if *fKey == "" {
		log.Fatal("Please provide the path to the private key")
	}

	cfg := gdata.DefaultConfig()
	cfg.LoadKey(*fKey)

	server, err := gdata.NewServer(cfg)
	if err != nil {
		log.Fatal(err)
	}

	http.ListenAndServe(*fPort, server)
}
