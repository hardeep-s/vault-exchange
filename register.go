package main

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)



func pathRegisterGroup(b *backend) *framework.Path {
	groupObject := &groupMeta{
        configobj: createConfigObject(b),
    }   
	return &framework.Path{
		Pattern: "register/group",
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Group name to register",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: groupObject.registerGroups,
		},
	}
}

