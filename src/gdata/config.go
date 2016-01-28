package gdata

import (
	"crypto/ecdsa"
	"io/ioutil"

	"github.com/vektra/jwt-go"
)

type Config struct {
	key *ecdsa.PrivateKey
}

func DefaultConfig() *Config {
	return &Config{}
}

func (c *Config) LoadKey(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	key, err := jwt.ParseECPrivateKeyFromPEM(data)
	if err != nil {
		return err
	}

	c.key = key

	return nil
}
