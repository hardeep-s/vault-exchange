package main

import (
	"context"
	"errors"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"encoding/json"
	//"github.com/hashicorp/go-hclog"
	"strings"
)


//registering a group includes creating  a path and corresponding policy for the group
func (b *backend) registerGroups(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	auth := strings.Split(req.DisplayName, "-")[0]
	user := strings.TrimPrefix(req.DisplayName, auth + "-")
	groupname := data.Get("name").(string)
    if groupname == "" {
		return logical.ErrorResponse("You need to provide  name for the group"), errors.New("You need to provide  name for the group")
	}
	groups,errgroups:=b.listGroups(ctx,req,user)
	if errgroups !=nil {
		trace.Println("Vault-Exchange PLUGIN TRACE ->register_group ","registerGroups-> GROUP LIST ERROR",errgroups,groups)
	}
	if groups[groupname]==nil {
		return logical.ErrorResponse("You can only register a group that you belong to "), errors.New("You can only register a group that you belong to")
	}
	return b.addGroups(groupname,"admin",ctx,req,data)
}

//add  group includes creating  a path and corresponding policy for the group
func (b *backend) addGroups(groupname,privileges string,ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	//trace.Println("Vault-Exchange PLUGIN TRACE ->register_group ","addGroups-> ", groupname,privileges)
	configEntry, err := b.readConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}

	c := &ClientMeta{
		ClientToken: configEntry.RootToken,
	}

	policy_name := "groups" + "-" + groupname
	policystr, err := c.createPolicy(configEntry, "groups", groupname, privileges,policy_name,"*")
	if err != nil {
			return logical.ErrorResponse("Failed to create a policy for " + groupname+ ", " + err.Error()), err
	}

	groupInfo, grouperr := c.read("/v1/identity/group/name/" + groupname)
	if(groupInfo == nil){
		err = c.createGroup(groupname, policy_name)
		if err != nil {
			return logical.ErrorResponse("Failed to create group ",groupname, err.Error()), err
		}
		c.writeSecret(configEntry,groupname+"/group_secrets/donot_remove","Do not remove this key val")
	} else if grouperr == nil && groupInfo != nil{
		return logical.ErrorResponse(groupname + " is already registered"), err
	}

	return c.writePolicy(policy_name, policystr)
}


//get groups list from directory service
func (b *backend) listGroups(ctx context.Context, req *logical.Request,user string) (map[string](map[string]interface{}), error) {
	configEntry, err := b.readConfig(ctx, req)
	c := &ClientMeta{
		ClientToken: configEntry.RootToken,
	}
	//OKTA
	url:=configEntry.APIURL+"/users/"+string(user)+"/groups"
	token:= "SSWS "+configEntry.APIToken
	//OKTA

	grouplist,err :=c.REST("GET",url,token,nil ) 	
	if err!=nil {
		trace.Println("Vault-Exchange PLUGIN TRACE ->register_group ","listGroups->ERROR ",err)
		return nil, err
	}

	var groups [] map[string]interface{}
	json.Unmarshal(grouplist, &groups)
    var list map[string](map[string]interface{})
	list = make(map[string](map[string]interface{}))
	for i:=0; i<len(groups);i++ {
		var onegroup=groups[i]
		for key, value := range onegroup {
  			if(key=="profile")  {
				myMap := value.(map[string]interface{})
				for k, val := range myMap {
					if(k=="name") {
						name:=val.(string)
						list[name]=myMap
					}
				}
			}
		}
	}
	return  list,nil
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