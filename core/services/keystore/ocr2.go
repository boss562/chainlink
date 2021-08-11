package keystore

import (
	"encoding/json"
	"sync"
	"time"

	"gorm.io/gorm/clause"

	p2ppeer "github.com/libp2p/go-libp2p-core/peer"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"gorm.io/gorm"

	"github.com/smartcontractkit/chainlink/core/logger"
	"github.com/smartcontractkit/chainlink/core/services/keystore/keys/ocr2key"
	"github.com/smartcontractkit/chainlink/core/services/keystore/keys/p2pkey"
	"github.com/smartcontractkit/chainlink/core/store/models"
	"github.com/smartcontractkit/chainlink/core/utils"
)

type OCR2 struct {
	*gorm.DB
	password     string
	p2pkeys      map[p2pkey.PeerID]p2pkey.Key
	ocr2keys     map[models.Sha256Hash]ocr2key.KeyBundle
	scryptParams utils.ScryptParams
	mu           *sync.RWMutex
}

func newOCR2KeyStore(db *gorm.DB, scryptParams utils.ScryptParams) *OCR2 {
	return &OCR2{
		DB:           db,
		p2pkeys:      make(map[p2pkey.PeerID]p2pkey.Key),
		ocr2keys:     make(map[models.Sha256Hash]ocr2key.KeyBundle),
		scryptParams: scryptParams,
		mu:           new(sync.RWMutex),
	}
}

func (ks *OCR2) Unlock(password string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	var errs error

	p2pkeys, err := ks.FindEncryptedP2PKeys()
	errs = multierr.Append(errs, err)
	ocr2keys, err := ks.FindEncryptedOCR2KeyBundles()
	errs = multierr.Append(errs, err)

	for _, ek := range p2pkeys {
		k, err := ek.Decrypt(password)
		errs = multierr.Append(errs, err)
		if err != nil {
			continue
		}
		peerID, err := k.GetPeerID()
		if err != nil {
			continue
		}
		errs = multierr.Append(errs, err)
		ks.p2pkeys[p2pkey.PeerID(peerID)] = k
		logger.Debugw("Unlocked P2P key", "peerID", peerID)
	}
	for _, ek := range ocr2keys {
		k, err := ek.Decrypt(password)
		errs = multierr.Append(errs, err)
		if k != nil {
			ks.ocr2keys[k.ID] = *k
			logger.Debugw("Unlocked OCR2 key", "hash", k.ID)
		}
	}
	ks.password = password
	return errs
}

func (ks OCR2) DecryptedP2PKey(peerID p2ppeer.ID) (p2pkey.Key, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	k, exists := ks.p2pkeys[p2pkey.PeerID(peerID)]
	return k, exists
}

func (ks OCR2) DecryptedP2PKeys() (keys []p2pkey.Key) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	for _, key := range ks.p2pkeys {
		keys = append(keys, key)
	}

	return keys
}

func (ks OCR2) DecryptedOCR2key(hash models.Sha256Hash) (ocr2key.KeyBundle, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	k, exists := ks.ocr2keys[hash]
	return k, exists
}

func (ks OCR2) GenerateEncryptedP2PKey() (p2pkey.Key, p2pkey.EncryptedP2PKey, error) {
	key, err := p2pkey.CreateKey()
	if err != nil {
		return p2pkey.Key{}, p2pkey.EncryptedP2PKey{}, errors.Wrapf(err, "while generating new p2p key")
	}
	enc, err := key.ToEncryptedP2PKey(ks.password, ks.scryptParams)
	if err != nil {
		return p2pkey.Key{}, p2pkey.EncryptedP2PKey{}, errors.Wrapf(err, "while encrypting p2p key")
	}
	err = ks.UpsertEncryptedP2PKey(&enc)
	if err != nil {
		return p2pkey.Key{}, p2pkey.EncryptedP2PKey{}, err
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.p2pkeys[enc.PeerID] = key
	return key, enc, nil
}

func (ks OCR2) UpsertEncryptedP2PKey(k *p2pkey.EncryptedP2PKey) error {
	err := ks.
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "pub_key"}},
			DoUpdates: clause.Assignments(map[string]interface{}{
				"encrypted_priv_key": gorm.Expr("excluded.encrypted_priv_key"),
				"updated_at":         time.Now(),
				"deleted_at":         gorm.Expr("null"),
			}),
		}).
		Create(k).
		Error
	if err != nil {
		return errors.Wrapf(err, "while inserting p2p key")
	}
	return nil
}

func (ks OCR2) FindEncryptedP2PKeys() (keys []p2pkey.EncryptedP2PKey, err error) {
	return keys, ks.Order("created_at asc, id asc").Find(&keys).Error
}

func (ks OCR2) FindEncryptedP2PKeyByID(id int32) (*p2pkey.EncryptedP2PKey, error) {
	var key p2pkey.EncryptedP2PKey
	err := ks.Where("id = ?", id).First(&key).Error
	return &key, err
}

func (ks OCR2) ArchiveEncryptedP2PKey(key *p2pkey.EncryptedP2PKey) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	err := ks.Delete(key).Error
	if err != nil {
		return err
	}
	delete(ks.p2pkeys, key.PeerID)
	return nil
}

func (ks OCR2) DeleteEncryptedP2PKey(key *p2pkey.EncryptedP2PKey) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	err := ks.Unscoped().Delete(key).Error
	if err != nil {
		return err
	}
	delete(ks.p2pkeys, key.PeerID)
	return nil
}

func (ks OCR2) GenerateEncryptedOCR2KeyBundle() (ocr2key.KeyBundle, ocr2key.EncryptedKeyBundle, error) {
	key, err := ocr2key.NewKeyBundle()
	if err != nil {
		return ocr2key.KeyBundle{}, ocr2key.EncryptedKeyBundle{}, errors.Wrapf(err, "while generating the new OCR2 key bundle")
	}
	enc, err := key.Encrypt(ks.password, ks.scryptParams)
	if err != nil {
		return ocr2key.KeyBundle{}, ocr2key.EncryptedKeyBundle{}, errors.Wrapf(err, "while encrypting the new OCR2 key bundle")
	}
	err = ks.CreateEncryptedOCR2KeyBundle(enc)
	if err != nil {
		return ocr2key.KeyBundle{}, ocr2key.EncryptedKeyBundle{}, err
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.ocr2keys[enc.ID] = *key
	return *key, *enc, nil
}

// CreateEncryptedOCR2KeyBundle creates an encrypted OCR private key record
func (ks OCR2) CreateEncryptedOCR2KeyBundle(encryptedKey *ocr2key.EncryptedKeyBundle) error {
	err := ks.Create(encryptedKey).Error
	return errors.Wrapf(err, "while persisting the new encrypted OCR2 key bundle")
}

func (ks OCR2) UpsertEncryptedOCR2KeyBundle(encryptedKey *ocr2key.EncryptedKeyBundle) error {
	err := ks.
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "id"}},
			DoUpdates: clause.Assignments(map[string]interface{}{
				"encrypted_private_keys": gorm.Expr("excluded.encrypted_private_keys"),
				"updated_at":             time.Now(),
				"deleted_at":             gorm.Expr("null"),
			}),
		}).
		Create(encryptedKey).
		Error
	if err != nil {
		return errors.Wrapf(err, "while upserting ocr key")
	}
	return nil
}

// FindEncryptedOCR2KeyBundles finds all the encrypted OCR key records
func (ks OCR2) FindEncryptedOCR2KeyBundles() (keys []ocr2key.EncryptedKeyBundle, err error) {
	err = ks.Order("created_at asc, id asc").Find(&keys).Error
	return keys, err
}

// FindEncryptedOCR2KeyBundleByID finds an EncryptedKeyBundle bundle by its ID
func (ks OCR2) FindEncryptedOCR2KeyBundleByID(id models.Sha256Hash) (ocr2key.EncryptedKeyBundle, error) {
	var key ocr2key.EncryptedKeyBundle
	err := ks.Where("id = ?", id).First(&key).Error
	return key, err
}

// ArchiveEncryptedOCR2KeyBundle deletes the provided encrypted OCR key bundle
func (ks OCR2) ArchiveEncryptedOCR2KeyBundle(key *ocr2key.EncryptedKeyBundle) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	err := ks.Delete(key).Error
	if err != nil {
		return err
	}
	delete(ks.ocr2keys, key.ID)
	return nil
}

// DeleteEncryptedOCR2KeyBundle deletes the provided encrypted OCR key bundle
func (ks OCR2) DeleteEncryptedOCR2KeyBundle(key *ocr2key.EncryptedKeyBundle) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	err := ks.Unscoped().Delete(key).Error
	if err != nil {
		return err
	}
	delete(ks.ocr2keys, key.ID)
	return nil
}

// ImportP2PKey imports a p2p key to the database
func (ks OCR2) ImportP2PKey(keyJSON []byte, oldPassword string) (*p2pkey.EncryptedP2PKey, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	var encryptedExport p2pkey.EncryptedP2PKeyExport
	err := json.Unmarshal(keyJSON, &encryptedExport)
	if err != nil {
		return nil, errors.Wrap(err, "invalid p2p key json")
	}
	privateKey, err := encryptedExport.DecryptPrivateKey(oldPassword)
	if err != nil {
		return nil, err
	}
	encryptedKey, err := privateKey.ToEncryptedP2PKey(ks.password, utils.DefaultScryptParams)
	if err != nil {
		return nil, err
	}
	err = ks.UpsertEncryptedP2PKey(&encryptedKey)
	if err != nil {
		return nil, err
	}
	ks.p2pkeys[encryptedKey.PeerID] = *privateKey

	return &encryptedKey, nil
}

// ExportP2PKey exports a p2p key from the database
func (ks OCR2) ExportP2PKey(ID int32, newPassword string) ([]byte, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	emptyExport := []byte{}
	encryptedP2PKey, err := ks.FindEncryptedP2PKeyByID(ID)
	if err != nil {
		return emptyExport, errors.Wrap(err, "unable to find p2p key with given ID")
	}
	decryptedP2PKey, err := encryptedP2PKey.Decrypt(ks.password)
	if err != nil {
		return emptyExport, errors.Wrap(err, "unable to decrypt p2p key with given keystore password")
	}
	encryptedExport, err := decryptedP2PKey.ToEncryptedExport(newPassword, utils.DefaultScryptParams)
	if err != nil {
		return emptyExport, errors.Wrap(err, "unable to encrypt p2p key for export with provided password")
	}

	return encryptedExport, nil
}

// ImportOCR2KeyBundle imports an OCR key bundle to the database
func (ks OCR2) ImportOCR2KeyBundle(keyJSON []byte, oldPassword string) (*ocr2key.EncryptedKeyBundle, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	var encryptedExport ocr2key.EncryptedOCR2KeyExport
	err := json.Unmarshal(keyJSON, &encryptedExport)
	if err != nil {
		return nil, errors.Wrap(err, "invalid OCR2 key json")
	}
	privateKey, err := encryptedExport.DecryptPrivateKey(oldPassword)
	if err != nil {
		return nil, err
	}
	encryptedKey, err := privateKey.Encrypt(ks.password, utils.DefaultScryptParams)
	if err != nil {
		return nil, err
	}
	err = ks.UpsertEncryptedOCR2KeyBundle(encryptedKey)
	if err != nil {
		return nil, err
	}
	ks.ocr2keys[privateKey.ID] = *privateKey

	return encryptedKey, nil
}

// ExportOCR2KeyBundle exports an OCR key bundle from the database
func (ks OCR2) ExportOCR2KeyBundle(id models.Sha256Hash, newPassword string) ([]byte, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	emptyExport := []byte{}
	encryptedP2PKey, err := ks.FindEncryptedOCR2KeyBundleByID(id)
	if err != nil {
		return emptyExport, errors.Wrap(err, "unable to find OCR2 key with given ID")
	}
	decryptedP2PKey, err := encryptedP2PKey.Decrypt(ks.password)
	if err != nil {
		return emptyExport, errors.Wrap(err, "unable to decrypt p2p key with given keystore password")
	}
	encryptedExport, err := decryptedP2PKey.ToEncryptedExport(newPassword, utils.DefaultScryptParams)
	if err != nil {
		return emptyExport, errors.Wrap(err, "unable to encrypt p2p key for export with provided password")
	}

	return encryptedExport, nil
}
