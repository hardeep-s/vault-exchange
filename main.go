package main

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
	"errors"
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
	APIToken  string `json:"authz_token"`
	APIURL  string `json:"authz_url"`
	AdminGroup  string `json:"admin_group"`
	ServerCertPath  string `json:"server_certs"`
	ClientCertPath  string `json:"client_certs"`
	CERTSConfig map[string]string `json:"certs_config"`
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
			authzConfig(&b),
			pathEnableGroupToAccessPath(&b),
			pathSignCerts(&b),
			pathAddGroup(&b),
		}),
		BackendType: logical.TypeCredential,
	}
	return &b
}


//Parameters used for configuring this plugin. 
//It needs authentication method, path of registration as well as root token
func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "setup",
		Fields: map[string]*framework.FieldSchema{
			"root_token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Root token needed to make updates",
			},
			"root_path": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "kv",
				Description: "root path for secrets engine",
			},
			"admin_group": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "SSO Group  that will be the admin this vault",
			},
			"client_certs": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "",
				Description: "path for generating client certs ",
			},
			"server_certs": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "DUMMY/Path/will/Not/Work",
				Description: "path for generating server certs ",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.writeConfig,
		},
	}
}


func authzConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/authz",
		Fields: map[string]*framework.FieldSchema{
			"api_token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Authorization token needed to access directory service api",
			},
			"api_url": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "directory service url",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.updateConfig,
		},
	}
}




//configure the command used for registering a group
func pathSignCerts(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "create/clientcert",
		Fields: map[string]*framework.FieldSchema{
			"type": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "x509",
				Description: "Type X509 or SSH",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.generateCert,
		},
	}
}

//configure the command used for registering a group
func pathAddGroup(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "register/group",
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Group name to register",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.registerGroups,
		},
	}
}

//configure the command used for registering a group
func pathEnableGroupToAccessPath(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "grant/access/group",
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Group name to register",
			},
			"path": &framework.FieldSchema{
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
		Pattern: "grant/access/awsrole",
		Fields: map[string]*framework.FieldSchema{
			"path": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "group path in the groups_secrets to share",
			},
			"privilege": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:	"r",
				Description: "r,w,rw, read/write privilege to the group path",
			},
			"role_arn": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "ARN of the AWS role that will acess the path.",
			},
			"ttl": &framework.FieldSchema{
				Type:		framework.TypeString,
				Default:	"0.5h",
				Description: "TTL for the token your role use.",
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
		Pattern: "grant/access/kubernetes",
		Fields: map[string]*framework.FieldSchema{
			"path": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "group path in the groups_secrets to share",
			},
			"privilege": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:	"r",
				Description: "r,w,rw, read/write privilege to the group path",
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
			"ttl": &framework.FieldSchema{
				Type:		framework.TypeString,
				Default:	"0.5h",
				Description: "TTL for the token your role use.",
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
		RootToken: data.Get("root_token").(string),
		RootPath:  data.Get("root_path").(string),
		AdminGroup:  data.Get("admin_group").(string),
		ServerCertPath:  data.Get("server_certs").(string),
		ClientCertPath:  data.Get("client_certs").(string),
	}
    if configinfo.RootToken == "" || configinfo.AdminGroup=="" {
		return logical.ErrorResponse("You need to provide  admin group and root token"), errors.New("You need to provide  admin group and root token")
	}
	configEntry, err := logical.StorageEntryJSON("config/info", configinfo)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, configEntry); err != nil {
		return nil, err
	}

	trace.Println("main->Vault-Exchange PLUGIN TRACE -> ","writeConfig->Done ")
	return b.addGroups(configinfo.AdminGroup,"su",ctx,req,data)
}

//write the plugin config to vault server
func (b *backend) updateConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	configEntry, err := b.readConfig(ctx, req)
	configEntry.APIToken=data.Get("api_token").(string)
	configEntry.APIURL=data.Get("api_url").(string)
	configinfo := &configData{
		RootToken: configEntry.RootToken,
		RootPath:  configEntry.RootPath,
		AdminGroup:  configEntry.AdminGroup,
		ServerCertPath:  configEntry.ServerCertPath,
		ClientCertPath:  configEntry.ClientCertPath,
		APIToken: data.Get("api_token").(string),
		APIURL: data.Get("api_url").(string),
	}
	configSave, err := logical.StorageEntryJSON("config/info", configinfo)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, configSave); err != nil {
		return logical.ErrorResponse("writePolicy->failed to  update config"), err
	}
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
		trace.Println("main->Vault-Exchange PLUGIN TRACE -> ",args)
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
