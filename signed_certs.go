package main

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"time"
	"errors"
	"strings"
)
const MAXTTL = time.Hour * 24

func (b *backend) generateClientCert(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	auth := strings.Split(req.DisplayName, "-")[0]
	user := strings.TrimPrefix(req.DisplayName, auth + "-")
	configEntry, err := b.readConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}
	ttl:=data.Get("ttl").(string)
	ttlValue, err := time.ParseDuration(ttl)
	if err != nil {
		return logical.ErrorResponse("Invalid TTL"), err
	} else if ttlValue > MAXTTL {
			return nil, errors.New("Maximum value of ttl can be  "+MAXTTL.String()+ " hours")
	}
	c := &ClientMeta{
		ClientToken: configEntry.RootToken,
	}
	body := map[string]string{
		"common_name": user,
		"max_ttl": ttl,
	}
	certtype := data.Get("type").(string)
	path := "/v1/"+configEntry.ClientCertPath  +"/issue/"+configEntry.CertRole
	if strings.ToLower(certtype) =="ssh" {
		path = "/v1/"+configEntry.ClientCertPath  
	}
	certObject,certerr:= c.writeCmd("POST",path , body )
	//trace.Println(""signed_certs->backend ->Vault-Exchange PLUGIN TRACE -> ","generateCert-> ",certObject,certerr)
	resp := &logical.Response{
		Data: certObject,
	}
	return resp, certerr
}

func (b *backend) generateServerCert(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	configEntry, err := b.readConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}
	c := &ClientMeta{
		ClientToken: configEntry.RootToken,
	}
	body := map[string]string{
		"common_name": data.Get("name").(string)+"."+configEntry.CertCN,
	}
	path := "/v1/"+configEntry.ServerCertPath  +"/issue/"+configEntry.CertRole 
	certObject,certerr:= c.writeCmd("POST",path , body )
	resp := &logical.Response{
		Data: certObject,
	}
	return resp, certerr
}


