package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"gdata"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

var (
	fPort    = flag.String("listen", ":12311", "Address to listen on")
	fMakeKey = flag.String("make-key", "", "Create a new key to sign JWTs with")
	fKey     = flag.String("key", "", "Private key to create JWTs with")
	fLEDir   = flag.String("encdir", "", "directory of TLS resources to use")
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

	if *fLEDir != "" {
		fmt.Printf("* Listening on TLS %s", *fPort)
		var (
			cert = filepath.Join(*fLEDir, "fullchain.pem")
			key  = filepath.Join(*fLEDir, "privkey.pem")
		)

		err = http.ListenAndServeTLS(*fPort, cert, key, server)

	} else {
		fmt.Printf("* Listening on %s", *fPort)
		err = http.ListenAndServe(*fPort, server)
	}

	if err != nil {
		log.Fatal(err)
	}
}
