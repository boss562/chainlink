package ocr2key

import (
	"encoding/json"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/pkg/errors"
	"github.com/smartcontractkit/chainlink/core/store/models"
	"github.com/smartcontractkit/chainlink/core/utils"
)

type EncryptedOCR2KeyExport struct {
	ID     models.Sha256Hash   `json:"id" gorm:"primary_key"`
	Crypto keystore.CryptoJSON `json:"crypto"`
}

func (pk *KeyBundle) ToEncryptedExport(auth string, scryptParams utils.ScryptParams) (export []byte, err error) {
	marshalledPrivK, err := json.Marshal(pk)
	if err != nil {
		return nil, err
	}
	cryptoJSON, err := keystore.EncryptDataV3(
		marshalledPrivK,
		[]byte(adulteratedPassword(auth)),
		scryptParams.N,
		scryptParams.P,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "could not encrypt OCR2 key")
	}

	encryptedOCR2KExport := EncryptedOCR2KeyExport{
		ID:     pk.ID,
		Crypto: cryptoJSON,
	}
	return json.Marshal(encryptedOCR2KExport)
}

// DecryptPrivateKey returns the PrivateKey in export, decrypted via auth, or an error
func (export EncryptedOCR2KeyExport) DecryptPrivateKey(auth string) (*KeyBundle, error) {
	marshalledPrivK, err := keystore.DecryptDataV3(export.Crypto, adulteratedPassword(auth))
	if err != nil {
		return nil, errors.Wrapf(err, "could not decrypt key %s", export.ID.String())
	}
	var pk KeyBundle
	err = json.Unmarshal(marshalledPrivK, &pk)
	if err != nil {
		return nil, errors.Wrapf(err, "could not unmarshal OCR private key %s", export.ID.String())
	}
	return &pk, nil
}
