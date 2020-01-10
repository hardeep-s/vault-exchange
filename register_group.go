package main

import (
	"context"
	"errors"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	//"github.com/hashicorp/go-hclog"
	"strings"
)




//registering a group includes creating  a path and corresponding policy for the group
func (b *backend) registerGroups(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	auth := strings.Split(req.DisplayName, "-")[0]
	user := strings.TrimPrefix(req.DisplayName, auth + "-")
	configEntry, err := b.readConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}
	groupname := data.Get("group_name").(string)
	trace.Println("Vault-Exchange PLUGIN TRACE -> ","registerGroups-> ",req.DisplayName,req.ControlGroup,auth,user, groupname)

	rc := &ClientMeta{
		ClientToken: data.Get("token").(string),
	}
	val,err1:=rc.readToken()
	trace.Println("AAAAAAAAA ->Vault-Exchange PLUGIN TRACE -> ","registerGroups-> ",val,err1)

	c := &ClientMeta{
		ClientToken: configEntry.RootToken,
	}
	c.writeSecret(configEntry,groupname+"/group_secrets/donot_remove","Do not remove this key val")

    if groupname == "" {
		return logical.ErrorResponse("You need to provide  name for the group"), errors.New("You need to provide  name for the group")
	}


	groupInfo, err := c.read("/v1/identity/group/name/" + groupname)
	if err == nil && groupInfo != nil{
		return logical.ErrorResponse(groupname + "is already registered"), err
	}

	policy_name := "groups" + "-" + groupname
	policystr, err := c.createPolicy(configEntry, "groups", groupname, "admin",policy_name,"*")

	if err != nil {
			return logical.ErrorResponse("Failed to create a policy for " + groupname+ ", " + err.Error()), err
	}
	if(groupInfo == nil){
		err = c.createGroup(groupname, policy_name)
		if err != nil {
			return logical.ErrorResponse("Failed to create group ",groupname, err.Error()), err
		}
	}

	return c.writePolicy(policy_name, policystr)
}

// Create internal group in Vault that map to an external OIDC group
func (c *ClientMeta) createGroup(name, policy string) ( error) {
	id_path := "/v1/identity/group"
	body := map[string]string{
		"name": name,
		"type": "external",
		"policies": policy,
	}
	client, err := c.Client()
	if err != nil {
		trace.Println("Vault-Exchange PLUGIN TRACE -> ","createGroup-Client->ERROR ",err)
		return err
	}
	r := client.NewRequest("POST", id_path)
	if err := r.SetJSONBody(body); err != nil {
		trace.Println("Vault-Exchange PLUGIN TRACE -> ","createGroup-SetJSONBody->ERROR ",err)
		return err
	}
	resp, err := client.RawRequest(r)
	defer resp.Body.Close()
	if err != nil {
		trace.Println("Vault-Exchange PLUGIN TRACE -> ","createGroup-RawRequest->ERROR ",err)
		return err
	}
	var result map[string]interface{}
	err = resp.DecodeJSON(&result)
	if err != nil {
		trace.Println("Vault-Exchange PLUGIN TRACE -> ","createGroup-DecodeJSON->ERROR ",err)
		return err
	}
	groupID := result["data"].(map[string]interface{})["id"]

	accessor, err := c.getAccessor()
	if err != nil {
		trace.Println("Vault-Exchange PLUGIN TRACE -> ","createGroup-getAccessor->ERROR ",err)
		return err
	}
	return c.createGroupAlias(name, groupID.(string), accessor.(string))
}

func (c *ClientMeta) getAccessor() (interface{}, error){
	path := "/v1/sys/auth"
	result, err := c.read(path)
	if err != nil {
		return nil, err
	}
	accessor := result["oidc/"].(map[string]interface{})["accessor"]
	return accessor, nil	
}

func (c *ClientMeta) createGroupAlias(name, group_id, accessor_id string) error {
	alias_path := "/v1/identity/group-alias"
	body := map[string]string{
		"name": name,
		"canonical_id": group_id,
		"mount_accessor": accessor_id,
	}
	return  c.write(alias_path, body)
}
