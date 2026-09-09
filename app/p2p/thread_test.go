package p2p

import (
	"context"
	"os"
	"testing"

	"github.com/bitcoinschema/go-bitcoin"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-alert-system/app/config"
	"github.com/bsv-blockchain/go-alert-system/app/models"
	"github.com/bsv-blockchain/go-alert-system/app/models/model"
	"github.com/bsv-blockchain/go-alert-system/utils"
)

// loadTestDependencies loads the test configuration with the three test keys active
func loadTestDependencies(t *testing.T) *config.Config {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, os.Setenv(config.EnvironmentKey, config.EnvironmentTest))

	deps, err := config.LoadDependencies(ctx, models.BaseModels, true)
	require.NoError(t, err)
	t.Cleanup(func() { deps.CloseAll(ctx) })

	for _, priv := range []string{utils.Key1, utils.Key2, utils.Key3} {
		var pub string
		pub, err = bitcoin.PubKeyFromPrivateKeyString(priv, true)
		require.NoError(t, err)

		key := models.NewPublicKey(model.WithAllDependencies(deps), model.New())
		key.Key = pub
		key.Active = true
		require.NoError(t, key.Save(ctx))
	}
	return deps
}

// signedAlertBytes builds a fully signed raw alert of the given type and sequence
func signedAlertBytes(t *testing.T, deps *config.Config, alertType models.AlertType, sequence uint32) []byte {
	t.Helper()
	alert := models.NewAlertMessage(model.WithAllDependencies(deps), model.New())
	alert.SetAlertType(alertType)
	alert.SetVersion(1)
	alert.SetTimestamp(1)
	alert.SequenceNumber = sequence
	alert.SetRawMessage([]byte{0x05, 'h', 'e', 'l', 'l', 'o'})
	alert.SerializeData()

	sigs, err := utils.SignWithKeys(alert.GetRawData(), []string{utils.Key1, utils.Key2, utils.Key3})
	require.NoError(t, err)
	alert.SetSignatures(sigs)
	return alert.Serialize()
}

// TestStreamThread_ProcessGotSequenceNumber covers validation of alerts received during sync
func TestStreamThread_ProcessGotSequenceNumber(t *testing.T) {
	t.Run("alert with an unexpected sequence number is rejected", func(t *testing.T) {
		deps := loadTestDependencies(t)
		thread := &StreamThread{config: deps, ctx: context.Background(), myLatestSequence: 0, latestSequence: 10}

		msg := &SyncMessage{
			Type:           IGotSequenceNumber,
			SequenceNumber: 7,
			Data:           signedAlertBytes(t, deps, models.AlertTypeInformational, 7),
		}
		require.ErrorIs(t, thread.ProcessGotSequenceNumber(msg), ErrUnexpectedSequenceNumber)
		require.Equal(t, uint32(0), thread.myLatestSequence)
	})

	t.Run("validly signed alert of an unknown type is rejected without panicking", func(t *testing.T) {
		deps := loadTestDependencies(t)
		thread := &StreamThread{config: deps, ctx: context.Background(), myLatestSequence: 0, latestSequence: 10}

		msg := &SyncMessage{
			Type:           IGotSequenceNumber,
			SequenceNumber: 1,
			Data:           signedAlertBytes(t, deps, models.AlertType(99), 1),
		}
		require.ErrorIs(t, thread.ProcessGotSequenceNumber(msg), models.ErrUnknownAlertType)
	})
}
