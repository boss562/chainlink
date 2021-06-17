package keystore_test

import (
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink/core/internal/cltest"
	"github.com/smartcontractkit/chainlink/core/internal/testutils/pgtest"
	"github.com/smartcontractkit/chainlink/core/services/keystore"
	"github.com/smartcontractkit/chainlink/core/services/keystore/keys/ethkey"
	"github.com/stretchr/testify/require"
)

func TestEthKeyStore_V2(t *testing.T) {
	t.Parallel()

	db := pgtest.NewGormDB(t)

	keyStore := keystore.ExposedNewMaster(db)
	keyStore.Unlock(cltest.Password)
	ethKeyStore := keyStore.Eth()
	reset := func() {
		keyStore.ResetXXXTestOnly()
		require.NoError(t, db.Exec("DELETE FROM encrypted_key_rings").Error)
		require.NoError(t, db.Exec("DELETE FROM eth_key_states").Error)
		keyStore.Unlock(cltest.Password)
	}

	t.Run("Create / All / AllStates / Get", func(t *testing.T) {
		defer reset()
		key, err := ethKeyStore.Create()
		require.NoError(t, err)
		retrievedKeys, err := ethKeyStore.GetAll()
		require.NoError(t, err)
		require.Equal(t, 1, len(retrievedKeys))
		require.Equal(t, key.Address, retrievedKeys[0].Address)
		foundKey, err := ethKeyStore.Get(key.Address.Hex())
		require.NoError(t, err)
		require.Equal(t, key, foundKey)
		// adds ethkey.State
		cltest.AssertCount(t, db, ethkey.State{}, 1)
		var state ethkey.State
		require.NoError(t, db.First(&state).Error)
		require.Equal(t, state.Address, retrievedKeys[0].Address)
		// adds key to db
		keyStore.ResetXXXTestOnly()
		keyStore.Unlock(cltest.Password)
		retrievedKeys, err = ethKeyStore.GetAll()
		require.NoError(t, err)
		require.Equal(t, 1, len(retrievedKeys))
		require.Equal(t, key.Address, retrievedKeys[0].Address)
		// adds 2nd key
		_, err = ethKeyStore.Create()
		require.NoError(t, err)
		retrievedKeys, err = ethKeyStore.GetAll()
		require.NoError(t, err)
		require.Equal(t, 2, len(retrievedKeys))
	})

	t.Run("RemoveKey", func(t *testing.T) {
		defer reset()
		key, err := ethKeyStore.Create()
		require.NoError(t, err)
		_, err = ethKeyStore.Delete(key.ID())
		require.NoError(t, err)
		retrievedKeys, err := ethKeyStore.GetAll()
		require.NoError(t, err)
		require.Equal(t, 0, len(retrievedKeys))
		cltest.AssertCount(t, db, ethkey.State{}, 0)
	})

	t.Run("SendingKeys / HasSendingKeyWithAddress / HasDBSendingKeys", func(t *testing.T) {
		defer reset()
		has, err := ethKeyStore.HasDBSendingKeys()
		require.NoError(t, err)
		require.False(t, has)
		key, err := ethKeyStore.Create()
		require.NoError(t, err)
		has, err = ethKeyStore.HasDBSendingKeys()
		require.NoError(t, err)
		require.True(t, has)
		sendingKeys, err := ethKeyStore.SendingKeys()
		require.NoError(t, err)
		require.Equal(t, 1, len(sendingKeys))
		require.Equal(t, key.Address, sendingKeys[0].Address)
		fundingKeys, err := ethKeyStore.FundingKeys()
		require.NoError(t, err)
		require.Equal(t, 0, len(fundingKeys))
		cltest.AssertCount(t, db, ethkey.State{}, 1)
		has, err = ethKeyStore.HasSendingKeyWithAddress(key.Address.Address())
		require.NoError(t, err)
		require.True(t, has)
		_, err = ethKeyStore.Delete(key.ID())
		require.NoError(t, err)
		cltest.AssertCount(t, db, ethkey.State{}, 0)
		has, err = ethKeyStore.HasSendingKeyWithAddress(key.Address.Address())
		require.NoError(t, err)
		require.False(t, has)
	})

	t.Run("EnsureKeys / FundingKeys / SendingKeys", func(t *testing.T) {
		defer reset()
		sKey, sDidExist, fKey, fDidExist, err := ethKeyStore.EnsureKeys()
		require.NoError(t, err)
		require.False(t, sDidExist)
		require.False(t, fDidExist)
		sendingKeys, err := ethKeyStore.SendingKeys()
		require.NoError(t, err)
		require.Equal(t, 1, len(sendingKeys))
		fundingKeys, err := ethKeyStore.FundingKeys()
		require.Equal(t, sKey.Address, sendingKeys[0].Address)
		require.NoError(t, err)
		require.Equal(t, 1, len(fundingKeys))
		require.Equal(t, fKey.Address, fundingKeys[0].Address)
		cltest.AssertCount(t, db, ethkey.State{}, 2)
	})

	t.Run("GetRoundRobinAddress", func(t *testing.T) {
		defer reset()
		// should error when no addresses
		_, err := ethKeyStore.GetRoundRobinAddress()
		require.Error(t, err)
		// should succeed when address present
		key, _, _, _, err := ethKeyStore.EnsureKeys()
		require.NoError(t, err)
		address, err := ethKeyStore.GetRoundRobinAddress()
		require.NoError(t, err)
		require.Equal(t, key.Address.Address(), address)
		err = db.Model(ethkey.State{}).
			Where("address = ?", key.Address).
			Update("last_used", time.Now().Add(-time.Hour)). // 1h ago
			Error
		require.NoError(t, err)
		// add 2nd key
		key2, err := ethKeyStore.Create()
		require.NoError(t, err)
		err = db.Model(ethkey.State{}).
			Where("address = ?", key2.Address).
			Update("last_used", time.Now().Add(-2*time.Hour)). // 2h ago
			Error
		require.NoError(t, err)
		address, err = ethKeyStore.GetRoundRobinAddress()
		require.NoError(t, err)
		require.Equal(t, key2.Address.Address(), address)
		err = db.Model(ethkey.State{}).
			Where("address = ?", key2.Address).
			Update("last_used", time.Now().Add(-10*time.Minute)). // 10 min ago
			Error
		require.NoError(t, err)
		address, err = ethKeyStore.GetRoundRobinAddress()
		require.NoError(t, err)
		require.Equal(t, key.Address.Address(), address)
		// with a whitelist
		address, err = ethKeyStore.GetRoundRobinAddress(key2.Address.Address(), cltest.NewAddress())
		require.NoError(t, err)
		require.Equal(t, key2.Address.Address(), address)
		//  should error when no keys match whitelist
		address, err = ethKeyStore.GetRoundRobinAddress(cltest.NewAddress(), cltest.NewAddress())
		require.Error(t, err)
	})
}
