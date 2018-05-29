package backend

import (
	"context"
	"encoding/json"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/mitchellh/mapstructure"
	"time"
)

func pathListRoles() *framework.Path {

	handler := func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		entries, err := req.Storage.List(ctx, "roles/")
		if err != nil {
			return nil, err
		}
		return logical.ListResponse(entries), nil
	}

	return &framework.Path{
		Pattern: "roles/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: handler,
		},

		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func pathRoles() *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
			"groups": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Names of the Kubernetes groups users authenticated via this role should be part of",
			},
			"extra": {
				Type:        framework.TypeMap,
				Description: "Extra fields to include in the UserInfo object returned to Kubernetes: A map of strings => list of strings",
			},
			"default_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default ttl for role.",
			},

			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Maximum time a credential is valid for",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.DeleteOperation: pathRolesDelete,
			logical.ReadOperation:   pathRolesRead,
			logical.UpdateOperation: pathRolesWrite,
		},

		HelpSynopsis:    pathRolesHelpSyn,
		HelpDescription: pathRolesHelpDesc,
	}
}

type extra map[string][]string

type roleEntry struct {
	Groups     []string      `json:"groups"`
	Extra      extra         `json:"extra"`
	DefaultTTL time.Duration `json:"default_ttl"`
	MaxTTL     time.Duration `json:"max_ttl"`
}

func pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "roles/"+d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func getRole(ctx context.Context, s logical.Storage, name string) (*roleEntry, error) {
	storageEntry, err := s.Get(ctx, "roles/"+name)
	if storageEntry == nil || err != nil {
		return nil, err
	}
	var role roleEntry
	err = json.Unmarshal(storageEntry.Value, &role)
	return &role, err
}

func pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	role, err := getRole(ctx, req.Storage, d.Get("name").(string))
	if role == nil || err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"groups":      role.Groups,
			"extra":       role.Extra,
			"default_ttl": role.DefaultTTL.Seconds(),
			"max_ttl":     role.MaxTTL.Seconds(),
		},
	}, nil
}

func pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	e := make(extra)
	err := mapstructure.Decode(d.Get("extra"), &e)
	if err != nil {
		return logical.ErrorResponse("extra must be a map: string -> list of strings"), nil
	}
	role := &roleEntry{
		Groups:     d.Get("groups").([]string),
		Extra:      e,
		DefaultTTL: time.Duration(d.Get("default_ttl").(int)) * time.Second,
		MaxTTL:     time.Duration(d.Get("max_ttl").(int)) * time.Second,
	}
	storageEntry, err := logical.StorageEntryJSON(
		"roles/"+d.Get("name").(string), role)
	if err != nil {
		return nil, err
	}
	return nil, req.Storage.Put(ctx, storageEntry)
}

const pathListRolesHelpSyn = `List the existing roles in this backend.`

const pathListRolesHelpDesc = `Roles will be listed by the role name.`

const pathRolesHelpSyn = `
Read, write and update roles controlling Kubernetes group membership and user extra fields.
`

const pathRolesHelpDesc = `
TODO
`
