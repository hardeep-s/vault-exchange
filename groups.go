package main

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"encoding/json"
	"strings"
	"errors"
	//"github.com/hashicorp/go-hclog"
)


type groupMeta struct {
    configobj *configMeta
}


func pathRegisterGroup(b *backend) *framework.Path {
	groupObject := &groupMeta{
        configobj: createConfigObject(b),
    }   
	return &framework.Path{
		Pattern: "register/group",
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Group name to register",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: groupObject.registerGroup,
		},
	}
}

func (groupobj *groupMeta) registerGroup(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupname := data.Get("name").(string)
    if groupname == "" {
		return logical.ErrorResponse("You need to provide  name for the group"), errors.New("You need to provide  name for the group")
	}
	found,err:=groupobj.checkIfMyGroup(ctx,req,groupname)
	if err !=nil {
		return logical.ErrorResponse("Error while fetching group info "), err
	}
	if found==false {
		return logical.ErrorResponse("You can only register a group that you belong to "), errors.New("You can only register a group that you belong to")
	}
	return groupobj.addGroups(groupname,"admin",ctx,req,data)
}



//add  group includes creating  a path and corresponding policy for the group
func (groupobj *groupMeta) addGroups(groupname,privileges string,ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	//trace.Println("Vault-Exchange PLUGIN TRACE ->register_group ","addGroups-> ", groupname,privileges)
	configEntry, err := groupobj.configobj.readConfig(ctx, req)
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

	groupInfo, err := c.read("/v1/identity/group/name/" + groupname)

	if(groupInfo == nil){
		err = c.createGroup(groupname, policy_name)
		if err != nil {
			return logical.ErrorResponse("Failed to create group ",groupname, err.Error()), err
		}
		c.writeSecret(configEntry,"groups",groupname+"/secrets/donot_remove","Do not remove this key val")
	}

	return c.writePolicy(policy_name, policystr)
}

 
func (groupobj *groupMeta) checkIfMyGroup(ctx context.Context, req *logical.Request,groupname string) (bool, error) {
	auth := strings.Split(req.DisplayName, "-")[0]
	user := strings.TrimPrefix(req.DisplayName, auth + "-")
	groups,err:=groupobj.listGroups(ctx,req,user)
	if err !=nil {
		trace.Println("Vault-Exchange PLUGIN TRACE ->register_group ","checkIfMyGroup-> GROUP LIST ERROR",err,groups)
		return false, err
	}
	return groups[groupname]!=nil,nil
}


//get groups list from directory service
func (groupobj *groupMeta) listGroups(ctx context.Context, req *logical.Request,user string) (map[string](map[string]interface{}), error) {
	configEntry, err := groupobj.configobj.readConfig(ctx, req)
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
