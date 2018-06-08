package backend

import (
	"context"
	"fmt"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"time"
)

func pathToken(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "token/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathTokenRead,
		},

		HelpSynopsis:    pathTokenReadHelpSyn,
		HelpDescription: pathTokenReadHelpDesc,
	}
}

type tokenEntry struct {
	Role           string    `json:"role"`
	ExpirationTime time.Time `json:"expiration_time"`
	Username       string    `json:"username"`
	UID            string    `json:"uid"`
	Groups         []string  `json:"groups"`
	Extra          Extra     `json:"extra"`
}

func (b *backend) pathTokenRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)
	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("Unknown role: %s", roleName)), nil
	}

	var username, uid string
	if req.EntityID != "" {
		// Use available entity information if we can.
		entity, err := b.System().EntityInfo(req.EntityID)
		if err != nil {
			return nil, err
		}
		uid = entity.ID
		if len(entity.Aliases) > 0 {
			// Take the first alias available for the username.
			alias := entity.Aliases[0]
			username = fmt.Sprintf("%s_%s", alias.Name, alias.MountAccessor)
		} else {
			// If no aliases, use the display name, role name, and entity ID.
			username = fmt.Sprintf("v_%s_%s_%s", req.DisplayName, roleName, uid)
		}
	} else {
		// If no entity, use the display name, role name, and a UUID.
		uid, err = uuid.GenerateUUID()
		if err != nil {
			return nil, err
		}
		username = fmt.Sprintf("v_%s_%s_%s", req.DisplayName, roleName, uid)
	}

	secret, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	// TODO: Explicit TTLs in requests?
	ttl, _, err := framework.CalculateTTL(b.System(), 0, role.DefaultTTL, 0, role.MaxTTL, 0, time.Time{})
	if err != nil {
		return nil, err
	}
	expiration := time.Now().Add(ttl + tokenExpireBuffer)

	entry := &tokenEntry{
		Role:           roleName,
		ExpirationTime: expiration,
		Username:       username,
		UID:            uid,
		Groups:         role.Groups,
		Extra:          role.Extra,
	}
	tokenPath, err := b.tokenPath(ctx, secret)
	if err != nil {
		return nil, err
	}
	storageEntry, err := logical.StorageEntryJSON(tokenPath, entry)
	if err := req.Storage.Put(ctx, storageEntry); err != nil {
		return nil, err
	}

	token := secret
	resp := b.Secret(SecretTokenType).Response(map[string]interface{}{
		"token": token,
	}, map[string]interface{}{
		"token_path": tokenPath,
		"role":       roleName,
	})
	resp.Secret.TTL = role.DefaultTTL
	resp.Secret.MaxTTL = role.MaxTTL
	return resp, nil
}

func (b *backend) tokenPath(ctx context.Context, secret string) (string, error) {
	s, err := b.Salt(ctx)
	if err != nil {
		return "", err
	}
	tokenIndex := s.SaltID(secret)
	return fmt.Sprintf("token/%s", tokenIndex), nil
}

const pathTokenReadHelpSyn = `
Request Kubernetes bearer token for a role.
`

const pathTokenReadHelpDesc = `
This path creates a Kubernetes bearer token for a certain role. The token will
expire at the end of its lease. Note that Kubernetes caches token validity for
a configurable amount of time (apiserver --authentication-token-webhook-cache-ttl,
default 2 minutes).
`
