package csakey

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
)

type Raw []byte

func (raw Raw) Key() KeyV2 {
	privKey := ed25519.PrivateKey(raw)
	return KeyV2{
		privateKey: &privKey,
		PublicKey:  ed25519PubKeyFromPrivKey(privKey),
	}
}

func (raw Raw) String() string {
	return "<CSA Raw Private Key>"
}

func (raw Raw) GoStringer() string {
	return raw.String()
}

type KeyV2 struct {
	privateKey *ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	Version    int
}

func NewV2() (KeyV2, error) {
	pubKey, privKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return KeyV2{}, err
	}
	return KeyV2{
		privateKey: &privKey,
		PublicKey:  pubKey,
		Version:    2,
	}, nil
}

func (key KeyV2) ID() string {
	return key.PublicKeyString()
}

func (key KeyV2) PublicKeyString() string {
	return hex.EncodeToString(key.PublicKey)
}

func (key KeyV2) Raw() Raw {
	return Raw(*key.privateKey)
}

func (key KeyV2) String() string {
	return fmt.Sprintf("CSAKeyV2{PrivateKey: <redacted>, PublicKey: %s}", key.PublicKey)
}

func (key KeyV2) GoStringer() string {
	return key.String()
}

func ed25519PubKeyFromPrivKey(privKey ed25519.PrivateKey) ed25519.PublicKey {
	publicKey := make([]byte, ed25519.PublicKeySize)
	copy(publicKey, privKey[32:])
	return ed25519.PublicKey(publicKey)
}
