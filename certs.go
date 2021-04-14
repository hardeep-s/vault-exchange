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
type certMeta struct {
    configobj *configMeta
}

func pathSignClientCert(b *backend) *framework.Path {
	certObject := &certMeta{
        configobj: createConfigObject(b),
    }   
	return &framework.Path{
		Pattern: "cert/client/create",
		Fields: map[string]*framework.FieldSchema{
			"type": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "x509",
				Description: "Type X509 or SSH",
			},
			"ttl": &framework.FieldSchema{
				Type:		framework.TypeString,
				Default:	"18h",
				Description: "duration for which the cert will be valid",
			},
			"ips": &framework.FieldSchema{
				Type:		framework.TypeString,
				Default:	"*",
				Description: "comma seperated list of source IP's from where the SSH cert is valid",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: certObject.generateClientCert,
		},
	}
}

func pathSignServerCert(b *backend) *framework.Path {
	certObject := &certMeta{
        configobj: createConfigObject(b),
    }   
	return &framework.Path{
		Pattern: "cert/server/create",
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "subdomain name",
			},
			"ttl": &framework.FieldSchema{
				Type:		framework.TypeString,
				Default:	"8760h",
				Description: "duration for which the cert will be valid",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: certObject.generateServerCert,
		},
	}
}
func (cert *certMeta) generateClientCert(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	auth := strings.Split(req.DisplayName, "-")[0]
	user := strings.TrimPrefix(req.DisplayName, auth + "-")
	configEntry, err := cert.configobj.readConfig(ctx, req)
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

func (cert *certMeta) generateServerCert(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	configEntry, err := cert.configobj.readConfig(ctx, req)
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


