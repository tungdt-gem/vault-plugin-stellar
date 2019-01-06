package stellar

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/stellar/go/keypair"
)

type Account struct {
	Address string
	Seed    string
}

func accountsPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "accounts/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.listAccounts,
			},
		},
		&framework.Path{
			Pattern:      "accounts/" + framework.GenericNameRegex("name"),
			HelpSynopsis: "Create a Stellar account keypair",
			Fields: map[string]*framework.FieldSchema{
				"xlm_balance": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Initial balance of XLM",
					Default:     "1",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.createAccount,
				logical.UpdateOperation: b.createAccount,
				logical.ReadOperation:   b.readAccount,
			},
		},
	}
}

// Returns a list of stored accounts (does not validate that the account is valid on Stellar)
func (b *backend) listAccounts(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	accountList, err := req.Storage.List(ctx, "accounts/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(accountList), nil
}

// Using Stellar's SDK, generates and stores an ED25519 asymmetric key pair
func (b *backend) createAccount(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	random, err := keypair.Random()
	if err != nil {
		log.Fatal(err)
	}

	address := random.Address()
	seed := random.Seed()

	log.Print("Public key : " + address)

	accountJSON := &Account{Address: address,
		Seed: seed}

	entry, err := logical.StorageEntryJSON(req.Path, accountJSON)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address":      address,
			"created_time": time.Now(),
		},
	}, nil
}

func (b *backend) readAccount(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	vaultAccount, err := b.readVaultAccount(ctx, req, req.Path)
	if err != nil {
		log.Fatal(err)
	}

	address := &vaultAccount.Address
	seed := &vaultAccount.Seed

	log.Print("Returning account...")
	return &logical.Response{
		Data: map[string]interface{}{
			"address":  address,
			"seed": seed,
		},
	}, nil
}

func (b *backend) readVaultAccount(ctx context.Context, req *logical.Request, path string) (*Account, error) {
	log.Print("Reading account from path: " + path)
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to find account at %s", path)
	}
	if entry == nil || len(entry.Value) == 0 {
		return nil, fmt.Errorf("no account found in storage")
	}

	log.Print("Deserializing account...")
	var account Account
	err = entry.DecodeJSON(&account)

	if entry == nil {
		return nil, fmt.Errorf("failed to deserialize account at %s", path)
	}

	return &account, err
}