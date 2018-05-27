package main

import (
	"context"
	"github.com/hashicorp/vault/helper/salt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"sync"
)

func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(c)
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend

	storage logical.Storage
	salt    *salt.Salt
	// TODO: Do we need to support invalidation + salt replacement?
	initSalt sync.Once
}

func Backend(c *logical.BackendConfig) *backend {
	b := &backend{
		storage: c.StorageView,
	}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"tokenreviews"},
		},
		Paths: []*framework.Path{
			pathRoles(),
			pathListRoles(),
			pathToken(b),
			pathReview(b),
		},
		Secrets: []*framework.Secret{
			secretToken(b),
		},
		// TODO: Invalidate, Clean.
	}

	return b
}

func (b *backend) Salt(ctx context.Context) (*salt.Salt, error) {
	var err error
	// Initialize the salt if needed.
	b.initSalt.Do(func() {
		b.salt, err = salt.NewSalt(ctx, b.storage, &salt.Config{
			HashFunc: salt.SHA256Hash,
			Location: salt.DefaultLocation,
		})
	})
	return b.salt, err
}
