package main

import (
	"context"
	"encoding/json"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"net/http"
	"time"
)

func pathReview(b *backend) *framework.Path {

	return &framework.Path{
		Pattern:      "tokenreviews",
		HelpSynopsis: "tokenreviews should be called by the Kubernetes webhook token authenticator to authenticate tokens",
		Fields: map[string]*framework.FieldSchema{
			"apiVersion": {
				Type:        framework.TypeString,
				Description: "Kubernetes API version string",
			},
			"kind": {
				Type:        framework.TypeString,
				Description: "Kubernetes object kind (must be TokenReview)",
			},
			"spec": {
				Type:        framework.TypeMap,
				Description: "Kubernetes TokenReview object spec",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathTokenReviewsUpdate,
		},
	}
}

func (b *backend) pathTokenReviewsUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	spec := d.Get("spec").(map[string]interface{})
	tokenRaw, ok := spec["token"]
	if !ok {
		return reviewResponseErr(
			http.StatusBadRequest, "no token in TokenReview request spec")
	}
	token, ok := tokenRaw.(string)
	if !ok {
		return reviewResponseErr(
			http.StatusBadRequest, "illegal non-string token in TokenReview request spec")
	}
	secret := token
	tokenPath, err := b.tokenPath(ctx, secret)
	if err != nil {
		return nil, err
	}

	rawEntry, err := req.Storage.Get(ctx, tokenPath)
	if err != nil {
		return nil, err
	}
	if rawEntry == nil {
		return reviewResponseDeny("token not found")
	}
	var entry tokenEntry
	if err := json.Unmarshal(rawEntry.Value, &entry); err != nil {
		return nil, err
	}
	if time.Now().After(entry.ExpirationTime) {
		return reviewResponseDeny("token expired")
	}
	// Allow - this is a valid, non-expired token.
	// CREATED matches k8s status code for non-error reviews.
	return reviewResponse(http.StatusCreated, map[string]interface{}{
		"authenticated": true,
		"user": map[string]interface{}{
			"username": entry.Username,
			"uid":      entry.UID,
			"groups":   entry.Groups,
			"extra":    entry.Extra,
		},
	}, auditData{"authenticated": true})
}

// In order to have more helpful audit logs on token reviews, we add extra data
// to our responses alongside the raw data sent to the client.
type auditData map[string]interface{}

// reviewResponseErr packages an error response for Kubernetes.
func reviewResponseErr(code int, err string) (*logical.Response, error) {
	return reviewResponse(code, map[string]interface{}{
		"authenticated": false,
		"error":         err,
	}, auditData{
		"authenticated": false,
		"error":         err,
	})
}

// reviewResponseDeny packages an error response for Kubernetes.
func reviewResponseDeny(reason string) (*logical.Response, error) {
	// Deny. HTTP code is OK, because we're not actually denying the review request -
	// just saying that the apiserver should deny the client.
	return reviewResponse(http.StatusCreated, map[string]interface{}{
		"authenticated": false,
	}, auditData{
		"authenticated": false,
		"deny_reason":   reason,
	})
}

// reviewResponse packages responses as expected by Kubernetes (including errors).
func reviewResponse(code int, status interface{}, auditData auditData) (*logical.Response, error) {
	response := map[string]interface{}{
		// TODO: Send back v1beta1 if that was in the request?
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenReview",
		"status":     status,
	}
	rawResponse, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	data := map[string]interface{}{
		logical.HTTPContentType: "application/json",
		logical.HTTPStatusCode:  code,
		logical.HTTPRawBody:     rawResponse,
	}
	for k, v := range auditData {
		data[k] = v
	}
	return &logical.Response{
		Data: data,
	}, nil
}
