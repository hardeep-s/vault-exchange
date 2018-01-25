package main

import (
	"fmt"
	"github.com/hashicorp/vault/helper/pluginutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/hashicorp/vault/logical/plugin"
	"github.com/hashicorp/vault/meta"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

const backendHelp = ` 
The "path-delegation" backend allows users to delegate access to their home paths to other users
`

var debuglevel int
var trace *log.Logger

type ClientMeta struct {
	meta.Meta
}

type TokenMeta struct {
	Username    string
	Expires     time.Time
	Expired     bool
	Path        string
	Policies    []interface{}
	PolicyFound bool
	DisplayName string
	AuthType string
}

func main() {
	EnableTrace("/tmp/vault-exchange.log")
	apiClientMeta := &pluginutil.APIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])
	Trace(0, "Delegate plugin started")

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := pluginutil.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		log.Fatal(err)
	}
}

func Factory(c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(c); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend
}

func Backend() *backend {
	var b backend
	Trace(0, "Delegate backend started")
	b.Backend = &framework.Backend{
		Help:        backendHelp,
		//BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"register",
			},
		},
		Paths: append([]*framework.Path{
			pathConfig(&b),
			pathRegister(&b),
			//pathGrant(&b),
			pathCommands(&b),
		}),
                BackendType: logical.TypeCredential,
	}
	return &b
}

func pathConfig(b *backend) *framework.Path {
	Trace(0, "Delegate->pathConfig ")
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "admin token needed to update policy",
			},
			"auth": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "ldap",
				Description: "Authentication type",
			},
			"path": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "CPE",
				Description: "root for user paths",
			},
			"debug": &framework.FieldSchema{
				Type:        framework.TypeInt,
				Default:     0,
				Description: "Trace level",
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
	Debug     int    `json:"debug"`
}

func (b *backend) writeConfig(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	Trace(0, " writeConfig", data, "CLIENTTOKEN=", req.ClientToken, "ENTITYID", req.EntityID)
	debuglevel = data.Get("debug").(int)
	configinfo := &configData{
		RootToken: data.Get("token").(string),
		RootPath:  data.Get("path").(string),
		AuthType:  data.Get("auth").(string),
		Debug:     debuglevel,
	}
	entry, err := logical.StorageEntryJSON("config/info", configinfo)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) readConfig(req *logical.Request) (*configData, error) {
	entry, err := req.Storage.Get("config/info")
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
	Trace(0,"CONFIG 3",result, &result,result.RootPath,result.RootToken)
	return &result, nil
}


func pathRegister(b *backend) *framework.Path {
	Trace(0, "PATH REGISTER START")
	return &framework.Path{
		Pattern: "register",
		Fields: map[string]*framework.FieldSchema{
			"user": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "User name.",
			},
			"path": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Path to delegate.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.registerUsers,
		},
	}
}

func pathCommands(b *backend) *framework.Path {
	Trace(0, "PATH COMMANDS START")
	return &framework.Path{
		Pattern: "command/" + framework.GenericNameRegex("command"),
		Fields: map[string]*framework.FieldSchema{
			"command": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "action to be taken",
			},

			"token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "User authentication toke.",
			},
			"path": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Path to delegate.",
			},
			"user": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "User to delegate the path to.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.runCommand,
		},
	}
}


func (b *backend) registerUsers(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	Trace(0, "registerUsers->  DATA=", data, "CLIENTTOKEN=", req.ClientToken)
	entry, err := b.readConfig(req)
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}
	user := data.Get("user").(string)
	c := &ClientMeta{
		Meta: meta.Meta{
			ClientToken: entry.RootToken,
			Ui:          nil,
		},
	}

	res,err := c.readUser(entry.AuthType,user)
	if res !=nil {
		return logical.ErrorResponse("User " + user + " is already registered"), nil
	}
	c.writeUser(entry.AuthType,user)
	policystr := b.accessPath(user,  entry.RootPath, "*")+
		"\" { capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"] }\n" +
		"path \"auth/exchange/command/*\" { capabilities = [\"update\"] } "
	return  c.writePolicy(user, policystr)
}






func (b *backend) runCommand(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	Trace(0, "runCommand-> PATH=", req.Path, "DATA=", data, "CLIENTTOKEN=", req.ClientToken, "ENTITYID", req.EntityID,  req.Headers)
	entry, err := b.readConfig(req)
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}
	cmdArr := strings.Split(req.Path, "/")
	if len(cmdArr) != 2 {
		return logical.ErrorResponse("invalid command"), nil
	}
	command := strings.ToLower(cmdArr[1])
	Trace(1, "runCommand> command =", command)

	token := data.Get("token").(string)
	Trace(1, "runCommand> token =", token)
	usertoken := b.verifyToken(req, token)
	if usertoken == nil || usertoken.Expired {
		return logical.ErrorResponse("invalid token"), nil
	}
	Trace(1, "runCommand> UserToken =", usertoken)
	Trace(1, "runCommand> UserToken 2 =", usertoken.Expired)
	c := &ClientMeta{
		Meta: meta.Meta{
			ClientToken: entry.RootToken,
			Ui:          nil,
		},
	}

	switch command {
	case "grant":
		return b.grantAccess(entry, usertoken, c, data)
	case "revoke":
		return b.revokeAccess(entry, usertoken, c, data)
	default:
	}
	return logical.ErrorResponse("invalid command"), nil

}


func (b *backend) grantAccess(entry *configData, usertoken *TokenMeta, c *ClientMeta, data *framework.FieldData) (*logical.Response, error) {
	path:=data.Get("path").(string)
	targetuser:=data.Get("user").(string)
	Trace(1,"grantAccess->",usertoken,path,targetuser)
	targetuserpolicy,err :=c.readPolicy(targetuser)
	if err != nil  || targetuserpolicy=="" {
		return logical.ErrorResponse("failed to load policy for " + targetuser), err
	}
	targetpath:=b.accessPath(usertoken.Username,  entry.RootPath, path)
	policystr := targetpath +"\" { capabilities = [\"read\"] }"
	targetuserpolicy=b.removeRuleFromPolicy(targetuserpolicy,targetpath)
	return c.writePolicy(usertoken.Username, targetuserpolicy+"\n"+policystr)
}
func (b *backend) revokeAccess(entry *configData, usertoken *TokenMeta, c *ClientMeta, data *framework.FieldData) (*logical.Response, error) {
	path:=data.Get("path").(string)
	targetuser:=data.Get("user").(string)
	Trace(1,"grantAccess->",usertoken,path,targetuser)
	targetuserpolicy,err :=c.readPolicy(targetuser)
	if err != nil  || targetuserpolicy=="" {
		return logical.ErrorResponse("failed to load policy for " + targetuser), err
	}
	targetuserpolicy=b.removeRuleFromPolicy(targetuserpolicy,b.accessPath(usertoken.Username,  entry.RootPath, path))
	return c.writePolicy(usertoken.Username, targetuserpolicy)
}

func (b *backend) accessPath(user,root, path string) string {
	return "path \"secret/" + root + "/" + user + "/"+strings.TrimLeft(path, "/")
}

func (b *backend) removeRuleFromPolicy(policy,path string) string {
	policyArray := strings.Split(policy,"\n")
	policstr:=""
	for i:=0;i<len(policyArray); i++ {
		if strings.Index(policyArray[i],path) == -1 {
			policstr+=strings.Trim(policyArray[i],"\n")+"\n"
		}
	}
	return policstr
}


func (c *ClientMeta) read(path string) (map[string]interface{}, error) {
      client, err := c.Client()
        if err != nil {
                Trace(0, "read->Client->Error", err)
                return  nil, err
        }

	r := client.NewRequest("GET", path)
	resp, err := client.RawRequest(r)
	Trace(2,"read->",resp,err)
	if resp != nil {
		defer resp.Body.Close()
		if resp.StatusCode == 404 {
			return nil, nil
		}
	}
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	err = resp.DecodeJSON(&result)
	return result,nil
}

func (c *ClientMeta) write(path string ,body map[string]string) ( error) {
	Trace(0,"write->Start->",path,body)
      	client, err := c.Client()
        if err != nil {
                Trace(0, "write->Client->Error", err)
                return   err
        }

	r := client.NewRequest("PUT", path)
	if err := r.SetJSONBody(body); err != nil {
		Trace(0,"write->SetJSONBody->Error",err)
		return  err
	}
	resp, err := client.RawRequest(r)
	Trace(0,"write->Response ",resp,err)
	defer resp.Body.Close()
	Trace(0,"DONE WRITE")
	return err
}


func (c *ClientMeta) readUser(authtype,name string) (interface {}, error) {
	result,err :=c.read("/v1/auth/"+authtype+"/users/"+name)
	Trace(0,"readUser->result",result, err)
	if err ==nil {
		if policyRaw, ok := result["data"]; ok {
			Trace(0,"readUser->policyRaw->",policyRaw)
			return policyRaw,nil
		}
	}
	return nil ,err

}

func (c *ClientMeta) writeUser(authtype,name string) (error) {
	body := map[string]string{
		"policies": name,
	}
	return c.write("/v1/auth/"+authtype+"/users/"+name, body)
}

func (c *ClientMeta) readPolicy(name string) (string, error) {
	Trace(1, "readPolicy->", name)
	client, err := c.Client()
	if err != nil {
		Trace(0, "readPolicy->Client->Error", err)
		return  "", err
	}

	policy, err := client.Sys().GetPolicy(name)
	if  err != nil {
		Trace(0, "readPolicy->GetPolicy->Error", err)
		return "", err
	}
	Trace(0,"readPolicy->",policy)
	return policy, nil
}
func (c *ClientMeta) writePolicy(name, rules string) (*logical.Response, error) {
	Trace(2, "writePolicy->", name, rules)
	client, err := c.Client()
	if err != nil {
		return logical.ErrorResponse("writePolicy->failed io open client"), err
	}

	if err := client.Sys().PutPolicy(name, rules); err != nil {
		Trace(0, "writePolicy->PutPolicy->Error", err)
		return logical.ErrorResponse("writePolicy->failed to  write policy"), err
	}
	return nil,nil
}

func (b *backend) verifyToken(req *logical.Request, token string) *TokenMeta {
	Trace(10, "verifyToken", token)
	if token==""  {
		return nil
	}
	entry, _ := b.readConfig(req)
	c := &ClientMeta{
		Meta: meta.Meta{
			ClientToken: entry.RootToken,
			Ui:          nil,
		},
	}
	client, _ := c.Client()
	if client != nil && client.Auth() != nil {
		tk, _ := client.Auth().Token().Lookup(token)
		meta := tk.Data["meta"]
		mtop := meta.(map[string]interface{})
		username := mtop["username"].(string)
		const timeForm = "2018-01-27T22:26:24.667710605-08:00"
		expires, _ := time.Parse(time.RFC3339Nano, tk.Data["expire_time"].(string))
		path := tk.Data["path"].(string)
		diplayname := tk.Data["display_name"].(string)
		policies := tk.Data["policies"].([]interface{})
		policyfound := false
		for i := 0; i < len(policies); i++ {
			if policies[i].(string) == username {
				policyfound = true
			}
		}
		now := time.Now()
		t := &TokenMeta{
			Username:    username,
			Expires:     expires,
			Expired:     now.After(expires),
			Path:        path,
			Policies:    policies,
			PolicyFound: policyfound,
			DisplayName: diplayname,
		}
		if t.Path != "" {
			authpaths := strings.Split(t.Path,"/")
			if len(authpaths) >=4 && authpaths[3]==username {
				t.AuthType=authpaths[1]
			}
		}
		Trace(1, "verifyToken-> Returned Token", *t)
		return t
	}
	return nil
}

func Trace(level int, args ...interface{}) {
	if level <= debuglevel {
		trace.Println(args)
	}
}
func EnableTrace(filename string) {
	debuglevel = 10
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		trace = log.New(io.MultiWriter(file), "Exchange Plugin: ", log.Ldate|log.Ltime|log.Lshortfile)
	} else {
		trace = log.New(os.Stdout, "Exchange Plugin: ", log.Ldate|log.Ltime|log.Lshortfile)
	}
}
