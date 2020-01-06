package main

import (
	"context"
	"bytes"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
	"log"
	"os"
	"text/template"
)

const backendHelp = ` 
The "vault-exchange" backend allows users to grant access to secrets in their home paths to other users
`
var debuglevel int
var trace *log.Logger

type ClientMeta struct {
	ClientToken string
}

type backend struct {
	*framework.Backend
}

type Policy struct {
	RootPath, Idtype, Name string
}

const admin_policy = `
path "{{.RootPath}}/*" {capabilities = ["list"]}
path "{{.RootPath}}/secret/data/{{.Idtype}}/{{.Name}}/group_secrets/*" { capabilities = ["list", "create", "read", "update","delete", "sudo"]}
path "{{.RootPath}}/secret/metadata/{{.Idtype}}/{{.Name}}/group_secrets/*" { capabilities = ["list", "read", "delete"]}
`

const read_only_policy = `
path "{{.RootPath}}/secret/data/{{.Idtype}}/{{.Name}}/group_secrets/*" { capabilities = ["read"]}
path "{{.RootPath}}/secret/metadata/{{.Idtype}}/{{.Name}}/group_secrets/*" { capabilities = ["list", "read"]}
`
 
const write_only_policy = `
path "{{.RootPath}}/secret/data/{{.Idtype}}/{{.Name}}/group_secrets/*" { capabilities = ["update"]}
path "{{.RootPath}}/secret/metadata/{{.Idtype}}/{{.Name}}/group_secrets/*" { capabilities = ["update"]}
`
 

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
			pathRegister(&b),
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
				Default:     "exchange/home",
				Description: "root for user paths",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.writeConfig,
		},
	}
}

type configData struct {
	RootToken string `json:"root_token"`
	RootPath  string `json:"root_path"`
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

//configure the command used for registering a group
func pathRegister(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "register",
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


// Init a client running as root
func (c *ClientMeta) Client() (*api.Client, error) {
	config := api.DefaultConfig()
	client, err := api.NewClient(config)
	if err == nil {
		client.SetToken(c.ClientToken)
	}
	return client, err
}

//read contents from a path
func (c *ClientMeta) read(path string) (map[string]interface{}, error) {
	client, err := c.Client()
	if err != nil {
		Trace(0, "read->Client->Error", err)
		return nil, err
	}

	r := client.NewRequest("GET", path)
	resp, err := client.RawRequest(r)
	if resp != nil {
		defer resp.Body.Close()
		if resp.StatusCode == 404 {
			Trace(0, "read->Response->404",r.URL,resp.Body)
			return nil, nil
		}
	}
	if err != nil {
		Trace(0, "read->Response->ERROR", err)
		return nil, err
	}

	var result map[string]interface{}
	err = resp.DecodeJSON(&result)
	return result, nil
}

//write contents to a path
func (c *ClientMeta) write(path string, body map[string]string) error {
	client, err := c.Client()
	if err != nil {
		Trace(0, "write->Client->Error", err)
		return err
	}

	r := client.NewRequest("PUT", path)
	if err := r.SetJSONBody(body); err != nil {
		Trace(0, "write->Response->SetJSONBody->Error", err)
		return err
	}
	resp, err := client.RawRequest(r)
	defer resp.Body.Close()
	return err
}

//check whether the user/group has already been registered
func (c *ClientMeta) readID(authtype, idtype, name string) (interface{}, error) {
	result, err := c.read("/v1/auth/" + authtype + "/" + idtype + "/" + name)
	if err != nil {
		return nil, err
	}
	if policyRaw, ok := result["data"]; ok {
		return policyRaw, nil
	}
	return nil, errors.New("error read identity data")

}

//map the policy for the user/group
func (c *ClientMeta) writeID(authtype, idtype, name, policy string) error {
	body := map[string]string{
		"policies": policy,
	}
	return c.write("/v1/auth/"+authtype+"/"+idtype+"/"+name, body)
}

func (c *ClientMeta) readToken() (interface{}, error) {
	result, err := c.read("/v1/auth/token/lookup")
	if err != nil {
		return nil, err
	}
	if policyRaw, ok := result["data"]; ok {
		return policyRaw, nil
	}
	return nil, errors.New("error read token data")

}

func (c *ClientMeta) writeSecret(configEntry *configData,path,comments string) error {
 	keyval := map[string]string{
        "comments": comments,
    }
	rrr:=c.write("/v1/"+configEntry.RootPath+"/secret/data/groups/"+path, keyval)
	return rrr;
}


func (c *ClientMeta) createPolicy(configEntry *configData, idtype, name, privileges,policy_name string, ) (string, error) {
	policyMetaData := Policy{
		RootPath: configEntry.RootPath,
		Idtype: idtype,
		Name: name,
	}
	policyData, err := template.New(policy_name).Parse(read_only_policy)
	if privileges=="admin" {
		policyData, err = template.New(policy_name).Parse(admin_policy)
	} else {
		policyData, err = template.New(policy_name).Parse(write_only_policy)
	}
	if err != nil {
		return "", err
	}
	var policyObject bytes.Buffer
	err = template.Must(policyData, err).Execute(&policyObject, policyMetaData)
	if err != nil {
		return "", err
	}
	return policyObject.String(), nil
}

//write a policy to Vault
func (c *ClientMeta) writePolicy(name, rules string) (*logical.Response, error) {
	client, err := c.Client()
	if err != nil {
		return logical.ErrorResponse("writePolicy->failed io open client"), err
	}

	if err := client.Sys().PutPolicy(name, rules); err != nil {
		return logical.ErrorResponse("writePolicy->failed to  write policy"), err
	}
	return nil, nil
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
