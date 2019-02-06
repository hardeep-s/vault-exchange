package main


/*
This part of code is used for granting access to own path to others, now it is still under developing
and not available to use. 

*/

import (
	"context"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"strings"
	"time"
)

func pathCommands(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "command/" + framework.GenericNameRegex("command"),
		Fields: map[string]*framework.FieldSchema{
			"command": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "action to be taken (grant/revoke)",
			},

			"token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Users authentication token",
			},
			"path": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Path to share.",
			},
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Target User or Group to grant access.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.runCommand,
		},
	}
}

func (b *backend) runCommand(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	Trace(8, "runCommand-> PATH=", req.Path, "DATA=", data)
	idtype := "users"
	entry, err := b.readConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}
	cmdArr := strings.Split(req.Path, "/")
	if len(cmdArr) != 2 {
		return logical.ErrorResponse("invalid command"), nil
	}
	command := strings.ToLower(cmdArr[1])
	if data.Get("path") == nil || data.Get("token") == nil || data.Get("user") == nil {
		return logical.ErrorResponse("insufficent arguments in the command"), nil
	}
	token := data.Get("token").(string)
	usertoken := b.verifyToken(ctx, req, token, idtype)
	if usertoken == nil || usertoken.Expired {
		return logical.ErrorResponse("invalid token"), nil
	}
	
	c := &ClientMeta{
		ClientToken: entry.RootToken,
	}
	path := data.Get("path").(string)
	targetuser := data.Get("name").(string)
	targetuserpolicy, err := c.readPolicy(targetuser)
	if err != nil || targetuserpolicy == "" {
		return logical.ErrorResponse("failed to load policy for " + targetuser), err
	}
	targetpath := b.accessPath(usertoken.Username, idtype, entry.RootPath, path)

	switch command {
	case "grant":
		policystr := targetpath + "\" { capabilities = [\"read\"] }"
		targetuserpolicy = b.removeRuleFromPolicy(targetuserpolicy, targetpath)
		return c.writePolicy(targetuser, targetuserpolicy+"\n"+policystr)
	case "revoke":
		targetuserpolicy = b.removeRuleFromPolicy(targetuserpolicy, targetpath)
		return c.writePolicy(targetuser, targetuserpolicy)
	default:
	}
	return logical.ErrorResponse("invalid command"), nil

}

func (b *backend) verifyToken(ctx context.Context, req *logical.Request, token string, idtype string) *TokenMeta {
	if token == "" {
		return nil
	}
	entry, _ := b.readConfig(ctx, req)
	c := &ClientMeta{
		ClientToken: entry.RootToken,
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
			authpaths := strings.Split(t.Path, "/")
			if len(authpaths) >= 4 && authpaths[3] == username {
				t.AuthType = authpaths[1]
			}
		}
		
		return t
	}
	return nil
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