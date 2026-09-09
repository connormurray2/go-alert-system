package models

import (
	"context"
	"encoding/binary"

	"github.com/bitcoinschema/go-bitcoin"

	"github.com/bsv-blockchain/go-alert-system/app/models/model"
	"github.com/bsv-blockchain/go-alert-system/utils"
)

// activateTestKeys stores the public keys derived from the given private keys as active keys
func (ts *TestSuite) activateTestKeys(privateKeys ...string) {
	for _, priv := range privateKeys {
		pub, err := bitcoin.PubKeyFromPrivateKeyString(priv, true)
		ts.Require().NoError(err)

		key := NewPublicKey(model.WithAllDependencies(ts.Dependencies), model.New())
		key.Key = pub
		key.Active = true
		ts.Require().NoError(key.Save(context.Background()))
	}
}

// newSignedTestAlert builds an informational alert and signs it with the given private keys
func (ts *TestSuite) newSignedTestAlert(signingKeys []string) *AlertMessage {
	alert := NewAlertMessage(model.WithAllDependencies(ts.Dependencies), model.New())
	alert.SetAlertType(AlertTypeInformational)
	alert.SetVersion(1)
	alert.SetTimestamp(1)
	alert.SequenceNumber = 1
	alert.SetRawMessage([]byte{0x05, 'h', 'e', 'l', 'l', 'o'})
	alert.SerializeData()

	sigs, err := utils.SignWithKeys(alert.GetRawData(), signingKeys)
	ts.Require().NoError(err)
	alert.SetSignatures(sigs)
	return alert
}

// TestAlertMessage_AreSignaturesValid covers the signature threshold rules
func (ts *TestSuite) TestAlertMessage_AreSignaturesValid() {
	ctx := context.Background()

	ts.Run("three signatures from three distinct active keys are valid", func() {
		ts.SetupTest()
		ts.activateTestKeys(utils.Key1, utils.Key2, utils.Key3, utils.Key4, utils.Key5)
		alert := ts.newSignedTestAlert([]string{utils.Key1, utils.Key2, utils.Key3})

		valid, err := alert.AreSignaturesValid(ctx)
		ts.Require().NoError(err)
		ts.Require().True(valid)
	})

	ts.Run("zero signatures are rejected", func() {
		ts.SetupTest()
		ts.activateTestKeys(utils.Key1, utils.Key2, utils.Key3)
		alert := ts.newSignedTestAlert([]string{utils.Key1, utils.Key2, utils.Key3})
		alert.SetSignatures(nil)

		valid, err := alert.AreSignaturesValid(ctx)
		ts.Require().NoError(err)
		ts.Require().False(valid)
	})

	ts.Run("fewer than three signatures are rejected", func() {
		ts.SetupTest()
		ts.activateTestKeys(utils.Key1, utils.Key2, utils.Key3)
		alert := ts.newSignedTestAlert([]string{utils.Key1, utils.Key2})

		valid, err := alert.AreSignaturesValid(ctx)
		ts.Require().NoError(err)
		ts.Require().False(valid)
	})

	ts.Run("three signatures from the same key are rejected", func() {
		ts.SetupTest()
		ts.activateTestKeys(utils.Key1, utils.Key2, utils.Key3)
		alert := ts.newSignedTestAlert([]string{utils.Key1, utils.Key1, utils.Key1})

		valid, err := alert.AreSignaturesValid(ctx)
		ts.Require().NoError(err)
		ts.Require().False(valid)
	})

	ts.Run("two distinct keys plus a repeat are rejected", func() {
		ts.SetupTest()
		ts.activateTestKeys(utils.Key1, utils.Key2, utils.Key3)
		alert := ts.newSignedTestAlert([]string{utils.Key1, utils.Key2, utils.Key1})

		valid, err := alert.AreSignaturesValid(ctx)
		ts.Require().NoError(err)
		ts.Require().False(valid)
	})

	ts.Run("a signature from an inactive key is rejected", func() {
		ts.SetupTest()
		ts.activateTestKeys(utils.Key1, utils.Key2, utils.Key3)
		alert := ts.newSignedTestAlert([]string{utils.Key1, utils.Key2, utils.Key4})

		valid, err := alert.AreSignaturesValid(ctx)
		ts.Require().NoError(err)
		ts.Require().False(valid)
	})

	ts.Run("a signature over different data is rejected", func() {
		ts.SetupTest()
		ts.activateTestKeys(utils.Key1, utils.Key2, utils.Key3)
		alert := ts.newSignedTestAlert([]string{utils.Key1, utils.Key2, utils.Key3})
		alert.SetRawMessage([]byte{0x05, 'w', 'o', 'r', 'l', 'd'})
		alert.SerializeData()

		valid, err := alert.AreSignaturesValid(ctx)
		ts.Require().NoError(err)
		ts.Require().False(valid)
	})

	ts.Run("no active keys returns an error", func() {
		ts.SetupTest()
		alert := ts.newSignedTestAlert([]string{utils.Key1, utils.Key2, utils.Key3})

		valid, err := alert.AreSignaturesValid(ctx)
		ts.Require().ErrorIs(err, ErrNoActivePublicKeys)
		ts.Require().False(valid)
	})
}

// TestAlertMessage_ReadRaw_SignatureLength ensures every alert type carries the full signature block
func (ts *TestSuite) TestAlertMessage_ReadRaw_SignatureLength() {
	buildAlert := func(alertType uint32, trailing int) []byte {
		raw := make([]byte, 0)
		raw = binary.LittleEndian.AppendUint32(raw, 1)
		raw = binary.LittleEndian.AppendUint32(raw, 1)
		raw = binary.LittleEndian.AppendUint64(raw, 1)
		raw = binary.LittleEndian.AppendUint32(raw, alertType)
		raw = append(raw, []byte("test")...)
		raw = append(raw, make([]byte, trailing)...)
		return raw
	}

	ts.Run("unknown alert type 99 does not get a reduced signature block", func() {
		alert := NewAlertMessage()
		alert.SetRawMessage(buildAlert(99, 128))
		ts.Require().ErrorIs(alert.ReadRaw(), ErrAlertMessageInvalidLength)
	})

	ts.Run("every alert type parses exactly three signatures", func() {
		for _, alertType := range []uint32{uint32(AlertTypeInformational), uint32(AlertTypeSetKeys), 99} {
			alert := NewAlertMessage()
			alert.SetRawMessage(buildAlert(alertType, RequiredSignatures*SignatureLength))
			ts.Require().NoError(alert.ReadRaw())
			ts.Require().Len(alert.signatures, RequiredSignatures)
			ts.Require().Equal([]byte("test"), alert.GetRawMessage())
		}
	})
}
