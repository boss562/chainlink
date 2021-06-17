package keystore

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/pkg/errors"
	"github.com/smartcontractkit/chainlink/core/services/keystore/keys/ethkey"
	"gorm.io/gorm"
)

//go:generate mockery --name Eth --output mocks/ --case=underscore

// Eth is the external interface for EthKeyStore
type Eth interface {
	Get(id string) (ethkey.KeyV2, error)
	GetAll() ([]ethkey.KeyV2, error)
	Create() (ethkey.KeyV2, error)
	Add(key ethkey.KeyV2) error
	Delete(id string) (ethkey.KeyV2, error)
	Import(keyJSON []byte, password string) (ethkey.KeyV2, error)
	Export(id string, password string) ([]byte, error)

	EnsureKeys() (ethkey.KeyV2, bool, ethkey.KeyV2, bool, error)
	SubscribeToKeyChanges() (ch chan struct{}, unsub func())

	SignTx(fromAddress common.Address, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)

	SendingKeys() (keys []ethkey.KeyV2, err error)
	FundingKeys() (keys []ethkey.KeyV2, err error)
	HasSendingKeyWithAddress(address common.Address) (bool, error)
	GetRoundRobinAddress(addresses ...common.Address) (address common.Address, err error)

	GetState(id string) (ethkey.State, error)
	GetStatesForKeys([]ethkey.KeyV2) ([]ethkey.State, error)

	// Does not require Unlock
	HasDBSendingKeys() (bool, error)

	GetV1KeysAsV2() ([]ethkey.KeyV2, []ethkey.State, error)
}

type eth struct {
	*keyManager
}

var _ Eth = eth{}

func newEthKeyStore(km *keyManager) eth {
	return eth{
		km,
	}
}

func (ks eth) Get(id string) (ethkey.KeyV2, error) {
	ks.lock.Lock()
	defer ks.lock.Unlock()
	if ks.isLocked() {
		return ethkey.KeyV2{}, ErrLocked
	}
	return ks.getByID(id)
}

func (ks eth) GetAll() (keys []ethkey.KeyV2, _ error) {
	ks.lock.RLock()
	defer ks.lock.RUnlock()
	if ks.isLocked() {
		return nil, ErrLocked
	}
	for _, key := range ks.keyRing.Eth {
		keys = append(keys, key)
	}
	return keys, nil
}

func (ks eth) Create() (ethkey.KeyV2, error) {
	ks.lock.Lock()
	defer ks.lock.Unlock()
	if ks.isLocked() {
		return ethkey.KeyV2{}, ErrLocked
	}
	key, err := ethkey.NewV2()
	if err != nil {
		return ethkey.KeyV2{}, err
	}
	return key, ks.add(key)
}

func (ks eth) Add(key ethkey.KeyV2) error {
	ks.lock.Lock()
	defer ks.lock.Unlock()
	if ks.isLocked() {
		return ErrLocked
	}
	if _, found := ks.keyRing.Eth[key.ID()]; found {
		return fmt.Errorf("key with ID %s already exists", key.ID())
	}
	return ks.add(key)
}

func (ks eth) EnsureKeys() (
	sendingKey ethkey.KeyV2,
	sendDidExist bool,
	fundingKey ethkey.KeyV2,
	fundDidExist bool,
	err error,
) {
	ks.lock.Lock()
	defer ks.lock.Unlock()
	if ks.isLocked() {
		return ethkey.KeyV2{}, false, ethkey.KeyV2{}, false, ErrLocked
	}
	// check & setup sending key
	sendingKeys, err := ks.sendingKeys()
	if err != nil {
		return ethkey.KeyV2{}, false, ethkey.KeyV2{}, false, err
	}
	if len(sendingKeys) > 0 {
		sendingKey = sendingKeys[0]
		sendDidExist = true
	} else {
		sendingKey, err = ethkey.NewV2()
		if err != nil {
			return ethkey.KeyV2{}, false, ethkey.KeyV2{}, false, err
		}
		err = ks.addEthKeyWithState(sendingKey, ethkey.State{IsFunding: false})
		if err != nil {
			return ethkey.KeyV2{}, false, ethkey.KeyV2{}, false, err
		}
	}
	// check & setup funding key
	fundingKeys, err := ks.fundingKeys()
	if err != nil {
		return ethkey.KeyV2{}, false, ethkey.KeyV2{}, false, err
	}
	if len(fundingKeys) > 0 {
		fundingKey = fundingKeys[0]
		fundDidExist = true
	} else {
		fundingKey, err = ethkey.NewV2()
		if err != nil {
			return ethkey.KeyV2{}, false, ethkey.KeyV2{}, false, err
		}
		err = ks.addEthKeyWithState(fundingKey, ethkey.State{IsFunding: true})
		if err != nil {
			return ethkey.KeyV2{}, false, ethkey.KeyV2{}, false, err
		}
	}
	return sendingKey, sendDidExist, fundingKey, fundDidExist, nil
}

func (ks eth) Import(keyJSON []byte, password string) (ethkey.KeyV2, error) {
	ks.lock.Lock()
	defer ks.lock.Unlock()
	if ks.isLocked() {
		return ethkey.KeyV2{}, ErrLocked
	}
	key, err := ethkey.FromEncryptedJSON(keyJSON, password)
	if err != nil {
		return ethkey.KeyV2{}, errors.Wrap(err, "EthKeyStore#ImportKey failed to decrypt key")
	}
	if _, found := ks.keyRing.Eth[key.ID()]; found {
		return ethkey.KeyV2{}, fmt.Errorf("key with ID %s already exists", key.ID())
	}
	return key, ks.add(key)
}

func (ks eth) Export(id string, password string) ([]byte, error) {
	ks.lock.RLock()
	defer ks.lock.RUnlock()
	if ks.isLocked() {
		return nil, ErrLocked
	}
	key, err := ks.getByID(id)
	if err != nil {
		return nil, err
	}
	return key.ToEncryptedJSON(password, ks.scryptParams)
}

func (ks eth) Delete(id string) (ethkey.KeyV2, error) {
	ks.lock.Lock()
	defer ks.lock.Unlock()
	if ks.isLocked() {
		return ethkey.KeyV2{}, ErrLocked
	}
	key, err := ks.getByID(id)
	if err != nil {
		return ethkey.KeyV2{}, err
	}
	err = ks.safeRemoveKey(key, func(db *gorm.DB) error {
		return db.Where("address = ?", key.Address).Delete(ethkey.State{}).Error
	})
	return key, err
}

func (ks eth) SubscribeToKeyChanges() (ch chan struct{}, unsub func()) {
	return nil, func() {}
}

func (ks eth) SignTx(address common.Address, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	ks.lock.RLock()
	defer ks.lock.RUnlock()
	if ks.isLocked() {
		return nil, ErrLocked
	}
	key, err := ks.getByID(address.Hex())
	if err != nil {
		return nil, err
	}
	signer := types.LatestSignerForChainID(chainID)
	return types.SignTx(tx, signer, key.ToEcdsaPrivKey())
}

func (ks eth) SendingKeys() (sendingKeys []ethkey.KeyV2, err error) {
	ks.lock.RLock()
	defer ks.lock.RUnlock()
	if ks.isLocked() {
		return nil, ErrLocked
	}
	return ks.sendingKeys()
}

func (ks eth) FundingKeys() (fundingKeys []ethkey.KeyV2, err error) {
	ks.lock.RLock()
	defer ks.lock.RUnlock()
	if ks.isLocked() {
		return nil, ErrLocked
	}
	return ks.fundingKeys()
}

func (ks eth) HasSendingKeyWithAddress(address common.Address) (bool, error) {
	ks.lock.RLock()
	defer ks.lock.RUnlock()
	if ks.isLocked() {
		return false, ErrLocked
	}
	_, err := ks.getEthKeyStateWhere("is_funding = ? AND address = ?", false, address)
	if err == gorm.ErrRecordNotFound {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func (ks eth) GetRoundRobinAddress(whitelist ...common.Address) (common.Address, error) {
	ks.lock.RLock()
	defer ks.lock.RUnlock()
	if ks.isLocked() {
		return common.Address{}, ErrLocked
	}
	state, err := ks.getNextRoundRobinAddress(whitelist)
	if err != nil {
		return common.Address{}, err
	}
	return state.Address.Address(), nil
}

func (ks eth) GetState(id string) (ethkey.State, error) {
	ks.lock.RLock()
	defer ks.lock.RUnlock()
	if ks.isLocked() {
		return ethkey.State{}, ErrLocked
	}
	key, err := ks.getByID(id)
	if err != nil {
		return ethkey.State{}, err
	}
	return ks.getEthKeyStateWhere("address = ?", key.Address)
}

func (ks eth) GetStatesForKeys(keys []ethkey.KeyV2) ([]ethkey.State, error) {
	var addresses []ethkey.EIP55Address
	for _, key := range keys {
		addresses = append(addresses, key.Address)
	}
	return ks.getEthKeyStatesWhere("address in ?", addresses)
}

// Does not require Unlock
func (ks eth) HasDBSendingKeys() (bool, error) {
	_, err := ks.getEthKeyStateWhere("is_funding = ?", false)
	if err == gorm.ErrRecordNotFound {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func (ks eth) GetV1KeysAsV2() (keys []ethkey.KeyV2, states []ethkey.State, _ error) {
	v1Keys, err := ks.GetEncryptedV1EthKeys()
	if err != nil {
		return keys, states, err
	}
	for _, keyV1 := range v1Keys {
		dKey, err := keystore.DecryptKey(keyV1.JSON, ks.password)
		if err != nil {
			return keys, states, err
		}
		keyV2 := ethkey.FromPrivateKey(dKey.PrivateKey)
		keys = append(keys, keyV2)
		state := ethkey.State{
			Address:   keyV1.Address,
			NextNonce: keyV1.NextNonce,
			IsFunding: keyV1.IsFunding,
		}
		states = append(states, state)
	}
	return keys, states, nil
}

func (ks eth) getByID(id string) (ethkey.KeyV2, error) {
	key, found := ks.keyRing.Eth[id]
	if !found {
		return ethkey.KeyV2{}, fmt.Errorf("unable to find eth key with id %s", id)
	}
	return key, nil
}

func (ks eth) fundingKeys() (fundingKeys []ethkey.KeyV2, err error) {
	states, err := ks.getEthKeyStatesWhere("is_funding = ?", true)
	if err != nil {
		return fundingKeys, err
	}
	for _, state := range states {
		fundingKeys = append(fundingKeys, ks.keyRing.Eth[state.KeyID()])
	}
	return fundingKeys, nil
}

func (ks eth) sendingKeys() (sendingKeys []ethkey.KeyV2, err error) {
	states, err := ks.getEthKeyStatesWhere("is_funding = ?", false)
	if err != nil {
		return sendingKeys, err
	}
	for _, state := range states {
		sendingKeys = append(sendingKeys, ks.keyRing.Eth[state.KeyID()])
	}
	return sendingKeys, nil
}

// caller must hold lock!
func (ks eth) add(key ethkey.KeyV2) error {
	return ks.addEthKeyWithState(key, ethkey.State{})
}

// caller must hold lock!
func (ks eth) addEthKeyWithState(key ethkey.KeyV2, state ethkey.State) error {
	state.Address = key.Address
	return ks.safeAddKey(key, func(db *gorm.DB) error {
		return db.Create(&state).Error
	})
}
