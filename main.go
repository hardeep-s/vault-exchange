package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
	//"github.com/hashicorp/go-hclog"
	"log"
	"os"
	"strings"
)

const backendHelp = ` 
The "vault-exchange" backend allows users to grant access to secrets in their home paths to other users
`
const authpath = "/v1/auth/"
var debuglevel int
var trace *log.Logger

type ClientMeta struct {
	ClientToken string
}

type backend struct {
	*framework.Backend
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
	Trace(0, "writeConfig->Begin ")
	configinfo := &configData{
		RootToken: data.Get("token").(string),
		RootPath:  data.Get("path").(string),
	}
	entry, err := logical.StorageEntryJSON("config/info", configinfo)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	Trace(0, "writeConfig-> End",configinfo.RootPath)
	return nil, nil
}

//when register users or groups, read the plugin configuration and use them as parameters in path creation
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

//configure the command used for registering a user/group
//when registering a user/group, you need to specify the name and the type of identity.
func pathRegister(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "register",
		Fields: map[string]*framework.FieldSchema{
			"group_name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Group name to register",
			},
			"user_name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "User name to register.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.registerUsersAndGroups,
		},
	}
}


// the function for registering a user/group. Read plugin configuration and create a path and corresponding policy for the user/group
func (b *backend) registerUsersAndGroups(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	auth := strings.Split(req.DisplayName, "-")[0]
	user := strings.TrimPrefix(req.DisplayName, auth + "-")
	entry, err := b.readConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}

	c := &ClientMeta{
		ClientToken: entry.RootToken,
	}

	groupname := data.Get("group_name").(string)
	userName := data.Get("user_name").(string)
	Trace(0, "registerUsersAndGroups-> 2",req.DisplayName,auth,user, groupname,userName)

    if groupname == "" && userName == "" {
		return logical.ErrorResponse("You need to provide  user_name or group_name"), errors.New("You need to provide a user or group name")
	} else if groupname != "" && userName != "" {
		return logical.ErrorResponse("You can register either a user_name or a group_name not both"), errors.New("You can register either a user or a group not both")
	}

	idtype := "users"
	name := userName
	if groupname != "" {
			idtype = "groups"
			name =groupname
	}

	res, err := c.readID(auth, idtype, name)
Trace(0,"LLLLLLLLLLLLLLL L",res,err)
	if res != nil {
		return logical.ErrorResponse("User " + idtype + " " + name + " is already registered"), nil
	}

	policy_name := idtype + "-" + name
	if c.writeID(auth, idtype, name,policy_name) != nil {
		return logical.ErrorResponse("Failed to create " + idtype + " " + name + " in the auth path"), nil
	}
	
	policystr := "path \"kv/data/" + entry.RootPath + "/" + idtype + "/" + name + "/*\" {\n capabilities = [\"create\", \"read\", \"update\", \"sudo\"]\n}\n" + 
				 "path \"kv/delete/" + entry.RootPath + "/" + idtype + "/" + name + "/*\" {\n capabilities = [\"update\"]\n}\n" + 
				 "path \"kv/undelete/" + entry.RootPath + "/" + idtype + "/" + name + "/*\" {\n capabilities = [\"update\"]\n}\n" + 
				 "path \"kv/destroy/" + entry.RootPath + "/" + idtype + "/" + name + "/*\" {\n capabilities = [\"update\"]\n}\n" + 
				 "path \"kv/metadata/" + entry.RootPath + "/" + idtype + "/" + name + "/*\" {\n capabilities = [\"list\",\"delete\",\"read\"]\n}\n" + 
				 "path \"kv/metadata/" + entry.RootPath + "/" + idtype + "/" + name + "/*\" {\n capabilities = [\"list\",\"read\"]\n}\n"
	
	return c.writePolicy(name, policystr)
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
Trace(0,"SSSSSSSSSS ",path)
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
Trace(0,"EEEEEEEEEEE ",path)
	resp, err := client.RawRequest(r)
Trace(0,"JJJJJJJJJJJ ",resp,err)
	defer resp.Body.Close()
	return err
}

//check whether the user/group has already been registered
func (c *ClientMeta) readID(authtype, idtype, name string) (interface{}, error) {
	result, err := c.read(authpath + authtype + "/" + idtype + "/" + name)
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
	return c.write(authpath+authtype+"/"+idtype+"/"+name, body)
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
