package stellar

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/stellar/go/keypair"
	"github.com/stellar/go/xdr"
	"log"
)

// Register the callbacks for the paths exposed by these functions
func signTransactionsPaths(b *stellarBackend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern:      "signTransactions",
			HelpSynopsis: "Sign a Stellar Transaction",
			Fields: map[string]*framework.FieldSchema{
				"txHash": &framework.FieldSchema {
					Type:        framework.TypeString,
					Description: "Raw Transaction Hash in hex string format",
				},
				"accountIDs": &framework.FieldSchema {
					Type:        framework.TypeStringSlice,
					Description: "List Account ID required to sign the transaction",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.signTransaction,
				logical.UpdateOperation: b.signTransaction,
			},
		},
	}
}

// Sign transaction with required signers and return signed payload.
func (b *stellarBackend) signTransaction(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Validate we didn't get extra fields
	err := validateFields(req, d)
	if err != nil {
		return nil, logical.CodedError(422, err.Error())
	}

	// Validate required fields are present
	txHash := d.Get("txHash").(string)
	if txHash == "" {
		return errMissingField("txHash"), nil
	}

	accountIDs := d.Get("accountIDs").([]string)
	if len(accountIDs) == 0 {
		return errMissingField("accountIDs"), nil
	}

	var signedSignatures []string
	for _, account := range accountIDs {
		accountInfo, err := b.readVaultAccount(ctx, req, "accounts/"+account)
		if err != nil {
			log.Fatal(err)
		}

		signature, err := signData(txHash, accountInfo.Seed)
		if err != nil {
			log.Fatal(err)
		}

		signedSignatures = append(signedSignatures, signature)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"signedTxs": signedSignatures,
		},
	}, nil
}

func signData(data string, signer string) (string, error) {
	skp := keypair.MustParse(signer)

	txHash, err := hex.DecodeString(data)
	if err != nil {
		return "", err
	}

	signature, err := skp.Sign(txHash[:])
	if err != nil {
		return "", err
	}

	ds := xdr.DecoratedSignature{
		Hint:      skp.Hint(),
		Signature: xdr.Signature(signature[:]),
	}

	dsBytes, err := ds.MarshalBinary()
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(dsBytes), nil
}
