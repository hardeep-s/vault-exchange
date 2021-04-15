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
type configMeta struct {
    b *backend
}

type configData struct {
	RootToken string `json:"root_token"`
	RootPath  string `json:"root_path"`
	APIToken  string `json:"authz_token"`
	APIURL  string `json:"authz_url"`
	AdminGroup  string `json:"admin_group"`
	ServerCertPath  string `json:"server_certs_pki"`
	ClientCertPath  string `json:"client_certs_pki"`
	CertRole  string `json:"cert_role"`
	CertCN  string `json:"certs_cn"`
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
			pathAuthZConfig(&b),
			pathSignServerCert(&b),
			pathSignClientCert(&b),
			pathRegisterGroup(&b),
			pathRegisterAWSRole(&b),
			pathGrantGroupAccess(&b),
			pathGrantGroupServerCert(&b),
			pathRevokeGroupServerCert(&b),
			pathGrantAWSServerCert(&b),
		}),
		BackendType: logical.TypeCredential,
	}
	return &b
}

func createConfigObject(b *backend) (*configMeta) {
	return &configMeta{
				b:b,
			}   
}
//Call to configure the plugin
func pathConfig(b *backend) *framework.Path {
	configobj:=createConfigObject(b)   
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
			"client_certs_pki": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "",
				Description: "path for generating client certs ",
			},
			"server_certs_pki": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "DUMMY/Path/will/Not/Work",
				Description: "path for generating server certs ",
			},
			"certs_role": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "issuecerts",
				Description: "role to issue certs ",
			},
			"certs_cn": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Common Name for Certs ",
			},
		},


		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: configobj.writeConfig,
		},
	}
}

//Call to configure OIDC API calls for group info
func pathAuthZConfig(b *backend) *framework.Path {
    configobj:= createConfigObject(b)
	return &framework.Path{
		Pattern: "authz/config",
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
			logical.UpdateOperation: configobj.updateConfig,
		},
	}
}

//write the plugin config to vault server
func (b *configMeta) writeConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	trace.Println("main->Vault-Exchange PLUGIN TRACE -> ","writeConfig->START ")
	configinfo := &configData{
		RootToken: data.Get("root_token").(string),
		RootPath:  data.Get("root_path").(string),
		AdminGroup:  data.Get("admin_group").(string),
		ServerCertPath:  data.Get("server_certs_pki").(string),
		ClientCertPath:  data.Get("client_certs_pki").(string),
		CertRole: data.Get("certs_role").(string),
		CertCN: data.Get("certs_cn").(string),
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
	groupObject := &groupMeta{
        configobj: b,
    }   
	return groupObject.addGroups(configinfo.AdminGroup,"su",ctx,req,data)
}

//write the plugin config to vault server
func (b *configMeta) updateConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	configEntry, err := b.readConfig(ctx, req)
	configEntry.APIToken=data.Get("api_token").(string)
	configEntry.APIURL=data.Get("api_url").(string)
	configinfo := &configData{
		RootToken: configEntry.RootToken,
		RootPath:  configEntry.RootPath,
		AdminGroup:  configEntry.AdminGroup,
		ServerCertPath:  configEntry.ServerCertPath,
		ClientCertPath:  configEntry.ClientCertPath,
		CertRole: configEntry.CertRole,
		CertCN: configEntry.CertCN,
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
func (b *configMeta) readConfig(ctx context.Context, req *logical.Request) (*configData, error) {
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

// ******************************public API's *********************************** 
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
