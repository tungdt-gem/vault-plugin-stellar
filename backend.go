package stellar

import (
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// Factory is used by framework
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

func FactoryType(backendType logical.BackendType) logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		b := backend()
		b.BackendType = backendType
		if err := b.Setup(ctx, conf); err != nil {
			return nil, err
		}
		return b, nil
	}
}

type stellarBackend struct {
	*framework.Backend
}

func backend() *stellarBackend {
	var b stellarBackend

	b.Backend = &framework.Backend{
		Help:        backendHelp,
		BackendType:  logical.TypeLogical,
		Secrets:      []*framework.Secret{},
		PathsSpecial: &logical.Paths{},
		Paths: framework.PathAppend(
			accountsPaths(&b),
			paymentsPaths(&b),
			signTransactionsPaths(&b),
		),
	}

	return &b
}

const (
	backendHelp = `
The Stellar backend plugin allows create, make payment and sign transaction using StellarGoSDK
`
)
