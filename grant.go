package main

import (
	"context"
	"errors"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
	"encoding/json"
)


type GRANT_PATHS struct {
	r, w string
}



func (b *backend) grantGroupAccess(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	source_group := data.Get("name").(string)
	body,err := b.readParams(req,data,"groups",source_group)
	if err !=nil {
		return logical.ErrorResponse("failed to readParams"), err
	}
	/*
	found,err:=b.checkIfMyGroup(ctx,req,body["groupname"],body["user"])
	if err !=nil {
		return logical.ErrorResponse("Error while fetching group info "), err
	}
	if found==false {
		return logical.ErrorResponse("You can only register a group that you belong to "), errors.New("You can only register a group that you belong to")
	}
	*/
	configEntry, err := b.readConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}

	c := &ClientMeta{
		ClientToken: configEntry.RootToken,
	}
	return c.updateGrantPolicy(configEntry,body,"groups","add",source_group)
}

func (b *backend) grantKubernetesRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rolename := data.Get("role").(string)
	bound_service_account_names := data.Get("service_account_name").(string)
	bound_service_account_namespaces := data.Get("service_account_namespace").(string)
	body := map[string]string{
		"bound_service_account_names": bound_service_account_names,
		"bound_service_account_namespaces": bound_service_account_namespaces,
	}
	return b.grantRole(ctx, req,  data , "kubernetes", rolename, body)
}

func (b *backend) grantAWSRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role := data.Get("role").(string)
	rolename := createUniqueRoleNameFromARN(role)
	body := map[string]string{
		"bound_iam_principal_arn": role,
		"auth_type":               "iam",
	}
	return b.grantRole(ctx, req,  data , "aws", rolename, body)
}

func (b *backend) grantRole(ctx context.Context,req *logical.Request,  data *framework.FieldData, authtype, rolename string, roleObject map[string]string ) (*logical.Response, error) {
	body,err := b.readParams(req,data,authtype,rolename)
	if err !=nil {
		return logical.ErrorResponse("failed to readParams"), err
	}
	/*
	found,err:=b.checkIfMyGroup(ctx,req,body["groupname"],body["user"])
	if err !=nil {
		return logical.ErrorResponse("Error while fetching group info "), err
	}
	if found==false {
		return logical.ErrorResponse("You can only register a group that you are a member of "), errors.New("You can only register a group that you belong to you")
	}
	*/
	configEntry, err := b.readConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}

	c := &ClientMeta{
		ClientToken: configEntry.RootToken,
	}
	res, err := c.readID(authtype, "role", rolename)
	if  res == nil {
		roleObject["policies"]=body["policy_name"]
		err= c.writeID(authtype, "role", rolename ,roleObject)
    	if err != nil {
			return logical.ErrorResponse("Failed to create AWS Role ID in Vault for  "+ rolename  +", " + err.Error()), errors.New("Failed to create AWS Role ID in Vault for  " +rolename + ", " + err.Error())
		}
	}
	return c.updateGrantPolicy(configEntry,body,authtype,"add", rolename)
}

func (b *backend) readParams(req *logical.Request, data *framework.FieldData, authtype,policyname string ) (map[string]string,error) {
	body := map[string]string{
		"path": data.Get("path").(string),
		"privilege" : data.Get("privilege").(string),
		"authtype" :authtype,
		"policy_name" : authtype + "-" +policyname,
		"auth":strings.Split(req.DisplayName, "-")[0],
	}
	body["user"] = strings.TrimPrefix(req.DisplayName, body["auth"] + "-")
	s := strings.Split(body["path"],"/")
	groupname :=s[0]	
	if(groupname=="") {
		if len(s) >1 {
			groupname=s[1]
		} else {
			return nil, errors.New("Invalid path "+body["path"])
		}
	} 
	body["groupname"]=groupname
	trace.Println("Vault-Exchange PLUGIN TRACE -> backend->grant->","readParams-> ",body)
	return body,nil
}

func createUniqueRoleNameFromARN(arn string) string {
	return strings.Split(strings.Split(arn, "::")[1], ":")[0] + "_" + strings.Split(arn, "/")[1]
}
 

//authtype=kubernetes,aws,kubernetes,groups
func (c *ClientMeta) updateGrantPolicy(configEntry *configData,body map[string]string,  authtype,action,granteename string) (*logical.Response, error)  {
	path:=body["path"]
	privilege:=body["privilege"]
	groupname:=body["groupname"]
	policy_name:=body["policy_name"]
	val, err := c.updateGrantMetadata("/v1/"+configEntry.RootPath+"/secret/metadata/"+authtype+"/group_grant/"+granteename, groupname ,action, path,privilege)
	if err !=nil {
		return logical.ErrorResponse("Failed to update metadata for " + granteename+ ", " + err.Error()), errors.New("Failed  to update metadata for  " + granteename+ ", " + err.Error())
	}
	_, err = c.updateGrantMetadata("/v1/"+configEntry.RootPath+"/secret/metadata/groups/"+groupname+"/group_access/"+authtype, granteename ,action, path,privilege)
	if err !=nil {
		return logical.ErrorResponse("Failed to update metadata for " + groupname+ ", " + err.Error()), errors.New("Failed  to update metadata for  " + groupname+ ", " + err.Error())
	}
	priv:="admin"
    if strings.Compare( configEntry.AdminGroup,granteename)==0 {
		priv="su"
	}
	policystr, err := c.createPolicy(configEntry, authtype, granteename, priv,policy_name,"*")
	readpaths :=strings.Split(val.r,";")
	for i:=0;i<len(readpaths) ;i++ {
		if len(readpaths[i])>1 {
			policystr = policystr+ "\npath \""+configEntry.RootPath+"/secret/data/groups/" +readpaths[i] +"\" { capabilities = [\"read\"]}"
		}
	}		
	writepaths :=strings.Split(val.w,";")
	for i:=0;i<len(writepaths) ;i++ {
		if len(writepaths[i])>1 {
			policystr = policystr+ "\npath \""+configEntry.RootPath+"/secret/data/groups/" + writepaths[i] +"\" { capabilities = [\"update\"]}\n"
		}
	}		
	return c.writePolicy(policy_name, policystr)
}


//Update the metadata for the authtype and group to document current mapping
func (c *ClientMeta) updateGrantMetadata(metapath, name ,action, path,privilege string) (GRANT_PATHS, error)  {
	result, err := c.read(metapath)
	var metadata  map[string]string
    if err == nil {
		metadata1,ok:=result["data"].(map[string]string)
		if !ok {
			metadata= make(map[string]string)
		} else {
			metadata=metadata1
		}
	} else {
		metadata= make(map[string]string)
	}
	valstr, ok := metadata[name]
	var val GRANT_PATHS
	if  ok {
		// first remove any existing refrence to the path for the specified privileges
		err =json.Unmarshal([]byte(valstr),val)
		if strings.Contains(privilege,"r") {
			if val.r !="" {
				val.r=strings.ReplaceAll(val.r,path+";","")
			}
		} 
		if strings.Contains(privilege,"w") {
			if val.w !="" {
				val.w=strings.ReplaceAll(val.w,path+";","")
			}
		} 
	}

	if action=="add" {
		// add the  path for the specified privileges
		if strings.Contains(privilege,"r") {
			val.r=val.r + path+";"
		}
		if strings.Contains(privilege,"w") {
			val.w=val.w + path+";"
		}
	}

	// update the metadata for the authtype
	out, err := json.Marshal(val)
	metadata[name]=string(out)
	return  val,c.write(metapath,metadata)
}

//*********************** Remove ****************************
/*
func (b *backend) tgrantRole(ctx context.Context,req *logical.Request,  data *framework.FieldData, authtype, rolename string, body map[string]string ) (*logical.Response, error) {
	configEntry, err := b.readConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}
	privilege := data.Get("privilege").(string)
	role := data.Get("role").(string)
	path := data.Get("path").(string)

	s := strings.Split(path,"/")
	groupname :=s[0]	
	if(groupname=="") {
		if len(s) >1 {
			groupname=s[1]
		} else {
			return logical.ErrorResponse("Invalid path"), errors.New("Invalid path")
		}
	} 

	ttlValue, err := time.ParseDuration(data.Get("ttl").(string))
	if err != nil {
		return logical.ErrorResponse("Invalid TTL "+err.Error()), err
	}
	if ttlValue > MAXTTL {
		return logical.ErrorResponse("Maximum value of ttl can be  48 hours"), errors.New("Maximum value of ttl can be  48 hours")
	}
	ttl := ttlValue.String()

	trace.Println("Vault-Exchange PLUGIN TRACE -> ","registerGroups-> ",req.DisplayName,req.ControlGroup,authtype,path, groupname,role,privilege,ttl)

	c := &ClientMeta{
		ClientToken: configEntry.RootToken,
	}
	res, err := c.readID(authtype, "role", rolename)
	if  res != nil {
		return logical.ErrorResponse( role + " is already registered"), errors.New(role + " is already registered")
	}
	policy_name := authtype + "-" + rolename
	body["policies"]=policy_name
	body["ttl"]=ttl

	err= c.writeID(authtype, "role", rolename ,body)
    if err != nil {
			return logical.ErrorResponse("Failed to create AWS Role ID in Vault for  "+ role  +", " + err.Error()), errors.New("Failed to create AWS Role ID in Vault for  " +role + ", " + err.Error())
	}

	return c.updateGrantPolicy(configEntry,authtype,"add", path,privilege, groupname,policy_name,rolename)
}
*/
