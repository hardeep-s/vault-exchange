package main

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
	"log"
	"os"
)

const backendHelp = ` 
The "vault-exchange" backend allows users to grant access to secrets in their home paths to other users
`
var debuglevel int
var trace *log.Logger

type backend struct {
	*framework.Backend
}

type configData struct {
	RootToken string `json:"root_token"`
	RootPath  string `json:"root_path"`
}
 

func main() {
	EnableTrace()
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		Trace(0, "main->","plugin shutting down", "error", err)
		os.Exit(1)
	}
}

func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend() *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: backendHelp,
		Paths: append([]*framework.Path{
			pathConfig(&b),
			pathRegisterGroup(&b),
		}),
		BackendType: logical.TypeCredential,
	}
	return &b
}


//Parameters used for configuring this plugin. 
//It needs authentication method, path of registration as well as root token
func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "admin token needed to make updates",
			},
			"path": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "kv",
				Description: "secret engine root path",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.writeConfig,
		},
	}
}

//configure the command used for registering a group
func pathRegisterGroup(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "registergroup",
		Fields: map[string]*framework.FieldSchema{
			"group_name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Group name to register",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.registerGroups,
		},
	}
}

// Grant Access  AWS Roles
func pathGrantAWSAccess(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "aws/grant",
		Fields: map[string]*framework.FieldSchema{
			"group_name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "",
				Description: "Groups name needs to be granted.",
			},
			"path": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "/",
				Description: "sub path in the groups_secrets to share",
			},
			"role_arn": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "",
				Description: "ARN of the AWS role that will acess the path.",
			},
			"privilege": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:	"r",
				Description: "r,w,rw, read/write privilege to the group path",
			},
			"ttl": &framework.FieldSchema{
				Type:		framework.TypeString,
				Default:	"0.5h",
				Description: "TTL for the token your role use.",
			},
			"token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "vault token",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.grantAWSRole,
		},
	}
}

// Grant Access  Kubernetes Roles
func pathGrantKubernetesAccess(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "kubernetes/grant",
		Fields: map[string]*framework.FieldSchema{
			"group_name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "",
				Description: "Groups name needs to be granted.",
			},
			"path": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "/",
				Description: "sub path in the groups_secrets to share",
			},
			"service_account_name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "",
				Description: "Service Account Name.",
			},
			"service_account_namespace": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "",
				Description: "Service Account Name namespace.",
			},
			"privilege": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:	"r",
				Description: "r,w,rw, read/write privilege to the group path",
			},
			"ttl": &framework.FieldSchema{
				Type:		framework.TypeString,
				Default:	"0.5h",
				Description: "TTL for the token your role use.",
			},
			"token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "vault token",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.grantKubernetesRole,
		},
	}
}

//write the plugin config to vault server
func (b *backend) writeConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	configinfo := &configData{
		RootToken: data.Get("token").(string),
		RootPath:  data.Get("path").(string),
	}
	configEntry, err := logical.StorageEntryJSON("config/info", configinfo)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, configEntry); err != nil {
		return nil, err
	}

	trace.Println("Vault-Exchange PLUGIN TRACE -> ","writeConfig->Done ")
	return nil, nil
}

//when register users or groups, read the plugin configuration and use them as parameters in path creation
func (b *backend) readConfig(ctx context.Context, req *logical.Request) (*configData, error) {
	configEntry, err := req.Storage.Get(ctx, "config/info")
	if err != nil {
		return nil, err
	}
	if configEntry == nil {
		return nil, nil
	}

	var result configData
	if err := configEntry.DecodeJSON(&result); err != nil {
		return nil, fmt.Errorf("error reading configuration: %s", err)
	}
	return &result, nil
}

// Application logs print to standard output
func Trace(level int, args ...interface{}) {
	if level <= debuglevel {
		trace.Println("Vault-Exchange PLUGIN TRACE -> ",args)
	}
}

func EnableTrace() {
	debuglevel = 0
	f, err := os.OpenFile("vault/log/vault-exchange.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		trace = log.New(os.Stdout, "Exchange Plugin: ", log.Ldate|log.Ltime|log.Lshortfile)
	} else {
		trace = log.New(f, "Exchange Plugin: ", log.Ldate|log.Ltime|log.Lshortfile)
	}
}
