package main

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/pluginutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/hashicorp/vault/logical/plugin"
	"log"
	"os"
	"strings"
	"time"
)

const backendHelp = ` 
The "vault-exchange" backend allows users to grant access to secrets in their home paths to other users
`

var debuglevel int
var trace *log.Logger

type ClientMeta struct {
	ClientToken string
}

type TokenMeta struct {
	Username    string
	Idtype      string
	Expires     time.Time
	Expired     bool
	Path        string
	Policies    []interface{}
	PolicyFound bool
	DisplayName string
	AuthType    string
}

type backend struct {
	*framework.Backend
}

func main() {
	EnableTrace()
	apiClientMeta := &pluginutil.APIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])
	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := pluginutil.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		log.Fatal(err)
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
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"register",
			},
		},
		Paths: append([]*framework.Path{
			pathConfig(&b),
			pathRegister(&b),
			pathCommands(&b),
		}),
		BackendType: logical.TypeCredential,
	}
	return &b
}

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "admin token needed to make updates",
			},
			"auth": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "ldap",
				Description: "Authentication type",
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
	AuthType  string `json:"auth_type"`
}

func (b *backend) writeConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	configinfo := &configData{
		RootToken: data.Get("token").(string),
		RootPath:  data.Get("path").(string),
		AuthType:  data.Get("auth").(string),
	}
	entry, err := logical.StorageEntryJSON("config/info", configinfo)
	if err != nil {
		return nil, err
	}

	Trace(0, configinfo, entry)
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) readConfig(ctx context.Context, req *logical.Request) (*configData, error) {
	entry, err := req.Storage.Get(ctx, "config/info")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result configData
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, fmt.Errorf("error reading configuration: %s", err)
	}
	return &result, nil
}

func pathRegister(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "register",
		Fields: map[string]*framework.FieldSchema{
			"type": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "user or group",
			},
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Users/Groups name.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.registerUsersAndGroups,
		},
	}
}



func (b *backend) registerUsersAndGroups(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	Trace(3, "registerUsers->  DATA=", data)
	entry, err := b.readConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}
	name := data.Get("name").(string)
	idtype := data.Get("type").(string)

	c := &ClientMeta{
		ClientToken: entry.RootToken,
	}

	res, err := c.readID(entry.AuthType, idtype, name)
	if res != nil {
		return logical.ErrorResponse("User " + idtype + " " + name + " is already registered"), nil
	}
	if c.writeID(entry.AuthType, idtype, name) != nil {
		return logical.ErrorResponse("Failed to create " + idtype + " " + name + " in the auth path"), nil
	}
	policystr := b.accessPath(name, idtype, entry.RootPath, "*") +
		"\" { capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"] }\n" +
		"path \"auth/exchange/command/*\" { capabilities = [\"update\"] } "
	return c.writePolicy(name, policystr)
}



func (b *backend) accessPath(name, idtype, root, path string) string {
	return "path \"secret/" + root + "/" +  idtype + "/" + name + "/" + strings.TrimLeft(path, "/")
}

func (b *backend) removeRuleFromPolicy(policy, path string) string {
	policyArray := strings.Split(policy, "\n")
	policstr := ""
	for i := 0; i < len(policyArray); i++ {
		if strings.Index(policyArray[i], path) == -1 {
			policstr += strings.TrimSpace(policyArray[i])
		}
	}
	return policstr
}

func (c *ClientMeta) Client() (*api.Client, error) {
	config := api.DefaultConfig()
	client, err := api.NewClient(config)
	if err == nil {
		client.SetToken(c.ClientToken)
	}
	return client, err
}
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
			Trace(0, "read->Response->404")
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

func (c *ClientMeta) readID(authtype, idtype, name string) (interface{}, error) {
	result, err := c.read("/v1/auth/" + authtype + "/" + idtype + "/" + name)
	if err == nil {
		if policyRaw, ok := result["data"]; ok {
			return policyRaw, nil
		}
	}
	return nil, err

}

func (c *ClientMeta) writeID(authtype, idtype, name string) error {
	body := map[string]string{
		"policies": name,
	}
	return c.write("/v1/auth/"+authtype+"/"+idtype+"/"+name, body)
}

func (c *ClientMeta) readPolicy(name string) (string, error) {
	client, err := c.Client()
	if err != nil {
		Trace(0, "readPolicy->Client->Error", err)
		return "", err
	}

	policy, err := client.Sys().GetPolicy(name)
	if err != nil {
		Trace(0, "readPolicy->GetPolicy->Error", err)
		return "", err
	}
	return policy, nil
}
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


func Trace(level int, args ...interface{}) {
	if level <= debuglevel {
		trace.Println(args)
	}
}
func EnableTrace() {
	trace = log.New(os.Stdout, "Exchange Plugin: ", log.Ldate|log.Ltime|log.Lshortfile)
}

/*
This part of code is used for granting access to own path to others, now it is still under developing
and not available to use. 

*/
