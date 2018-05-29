package backend

import (
	"context"
	"fmt"

	"encoding/json"
	"github.com/go-errors/errors"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"time"
)

const (
	// SecretTokenType is the secret type for Kubernetes bearer tokens issued by this backend.
	SecretTokenType = "kubernetes-token"
	// We add a small buffer to token expirations to ensure they do not expire before their
	// associated leases.
	tokenExpireBuffer = 1 * time.Second
)

func secretToken(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: SecretTokenType,
		Fields: map[string]*framework.FieldSchema{
			"token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Bearer token for Kubernetes webhook authentication",
			},
		},

		Renew:  b.secretTokenRenew,
		Revoke: b.secretTokenRevoke,
	}
}

func (b *backend) secretTokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Get the lease information
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, errors.New("secret is missing role internal data")
	}
	roleName, ok := roleRaw.(string)
	if !ok {
		return nil, errors.New("error converting role internal data to string")
	}
	tokenPathRaw, ok := req.Secret.InternalData["token_path"]
	if !ok {
		return nil, errors.New("secret is missing token_path internal data")
	}
	tokenPath, ok := tokenPathRaw.(string)
	if !ok {
		return nil, errors.New("error converting token_path internal data to string")
	}

	// Determine the new TTL.
	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, errors.New("role not found: " + roleName)
	}
	ttl, _, err := framework.CalculateTTL(b.System(), req.Secret.Increment, role.DefaultTTL, 0, role.MaxTTL, 0, req.Secret.IssueTime)
	if err != nil {
		return nil, err
	}
	// TODO: Check if ttl > 0?

	// Read the token storage entry, update its ttl, and write it back.
	storageEntry, err := req.Storage.Get(ctx, tokenPath)
	if err != nil {
		return nil, err
	}
	if storageEntry == nil {
		return nil, errors.New("token not found")
	}
	var token tokenEntry
	err = json.Unmarshal(storageEntry.Value, &token)
	if err != nil {
		return nil, err
	}
	token.ExpirationTime = time.Now().Add(ttl + tokenExpireBuffer)
	storageEntry, err = logical.StorageEntryJSON(tokenPath, token)
	if err := req.Storage.Put(ctx, storageEntry); err != nil {
		return nil, err
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = role.MaxTTL
	return resp, nil
}

func (b *backend) secretTokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Get the lease information
	tokenPathRaw, ok := req.Secret.InternalData["token_path"]
	if !ok {
		return nil, fmt.Errorf("secret is missing token_path internal data")
	}
	tokenPath, ok := tokenPathRaw.(string)
	if !ok {
		return nil, fmt.Errorf("error converting token_path internal data to string")
	}
	return nil, req.Storage.Delete(ctx, tokenPath)
}
