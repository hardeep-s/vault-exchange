package main

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
)




//registering a group includes creating  a path and corresponding policy for the group
func (b *backend) generateCert(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	auth := strings.Split(req.DisplayName, "-")[0]
	user := strings.TrimPrefix(req.DisplayName, auth + "-")
	configEntry, err := b.readConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}
	c := &ClientMeta{
		ClientToken: configEntry.RootToken,
	}
	body := map[string]string{
		"common_name": user,
	}
    //groups:=listGroups(ctx,req,user)
	certtype := data.Get("type").(string)
	var path string
	if strings.ToLower(certtype) =="ssh" {
	} else {
		path = "/v1/"+configEntry.ClientCertPath  // "/v1/upstart-client/issue/issuecerts"
	}
	certObject,certerr:= c.writeCmd("POST",path , body )
	trace.Println("DDDDDDDDDDDDDD ->Vault-Exchange PLUGIN TRACE -> ","generateCert-> ",certObject,certerr)
	resp := &logical.Response{
		Data: certObject,
	}
	return resp, certerr
}

