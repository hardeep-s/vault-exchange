package main

import (
	"context"
	"errors"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"time"
	"strings"
	"encoding/json"
)


const MAXTTL = time.Hour * 48
type GRANT_PATHS struct {
	r, w string
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

func (b *backend) grantRole(ctx context.Context,req *logical.Request,  data *framework.FieldData, authtype, rolename string, body map[string]string ) (*logical.Response, error) {
	configEntry, err := b.readConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}
	path := data.Get("path").(string)
	role := data.Get("role").(string)
	groupname := data.Get("group_name").(string)
	privilege := data.Get("privilege").(string)
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
func createUniqueRoleNameFromARN(arn string) string {
	return strings.Split(strings.Split(arn, "::")[1], ":")[0] + "_" + strings.Split(arn, "/")[1]
}
 
func checkIfMyRegisteredGroup(groupname, token string) ( error) {
	rc := &ClientMeta{
		ClientToken: token,
	}
	val,err:=rc.readToken()
	trace.Println("AAAAAAAAA ->Vault-Exchange PLUGIN TRACE -> ","checkIfMyRegisteredGroup-> ",groupname,val,err)
	//return errors.New("You are not a member of the group ",groupname)	
	return nil	
}

//Update the metadata for the authtype and group to document current mapping
func (c *ClientMeta) updateGrantPolicy(configEntry *configData, authtype,action, path,privilege, groupname,policy_name,rolename string) (*logical.Response, error)  {
	//Update group mapping  metadata for the authtype 
	val, err := c.updateGrantMetadata("/v1/"+configEntry.RootPath+"/secret/data/"+authtype+"/metadata/"+rolename, groupname ,action, path,privilege)
	if err !=nil {
		return logical.ErrorResponse("Failed to update metadata for " + rolename+ ", " + err.Error()), errors.New("Failed  to update metadata for  " + rolename+ ", " + err.Error())
	}

	//update authtype mapping metadata for group
	_, err = c.updateGrantMetadata("/v1/"+configEntry.RootPath+"/secret/data/groups/"+groupname+"/group_metadata/"+authtype, groupname ,action, path,privilege)
	if err !=nil {
		return logical.ErrorResponse("Failed to update metadata for " + groupname+ ", " + err.Error()), errors.New("Failed  to update metadata for  " + groupname+ ", " + err.Error())
	}

	//regenerate and update the policy for the auth type 
	policystr:=""
	readpaths :=strings.Split(val.r,";")
	for i:=0;i<len(readpaths) ;i++ {
		if len(readpaths[i])>1 {
			policystr = policystr+ "path \""+configEntry.RootPath+"/secret/data/groups/" + groupname + "/group_secrets/"+readpaths[i] +"\" { capabilities = [\"read\"]}\n"
		}
	}		
	writepaths :=strings.Split(val.w,";")
	for i:=0;i<len(writepaths) ;i++ {
		if len(writepaths[i])>1 {
			policystr = policystr+ "path \""+configEntry.RootPath+"/secret/data/groups/" + groupname + "/group_secrets/"+writepaths[i] +"\" { capabilities = [\"update\"]}\n"
		}
	}		
	return c.writePolicy(policy_name, policystr)
}


//Update the metadata for the authtype and group to document current mapping
func (c *ClientMeta) updateGrantMetadata(metapath, name ,action, path,privilege string) (GRANT_PATHS, error)  {
	//update authtype mapping metadata 
	result, err := c.read(metapath)
	var metadata  map[string]string
    if err == nil {
		metadata=result["data"].(map[string]string)
	} else {
		metadata= make(map[string]string)
	}
	//update  metadata 
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

