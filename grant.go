package main

import (
	"context"
	"errors"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
	//"encoding/json"
)

type GRANT_PATHS struct {
	r, w, e string
}

type GrantMeta struct {
    configobj *configMeta
}


func pathGrantGroupServerCert(b *backend) *framework.Path {
	grantObject := &GrantMeta{
        configobj: createConfigObject(b),
    }   
	return &framework.Path{
		Pattern: "grant/cert/group",
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the role that will be granted access",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: grantObject.grantGroupServerCert,
		},
	}
}

func pathRevokeGroupServerCert(b *backend) *framework.Path {
	grantObject := &GrantMeta{
        configobj: createConfigObject(b),
    }   
	return &framework.Path{
		Pattern: "revoke/cert/group",
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the role that will be granted access",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: grantObject.revokeGroupServerCert,
		},
	}
}

func pathGrantAWSServerCert(b *backend) *framework.Path {
	grantObject := &GrantMeta{
        configobj: createConfigObject(b),
    }   
	return &framework.Path{
		Pattern: "grant/cert/aws",
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the role that will be granted access",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: grantObject.grantAWSServerCert,
		},
	}
}

func pathGrantGroupAccess(b *backend) *framework.Path {
	grantObject := &GrantMeta{
        configobj: createConfigObject(b),
    }   

	return &framework.Path{
		Pattern: "grant/access/group",
		Fields: map[string]*framework.FieldSchema{
			"privilege": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:	"r",
				Description: "r,w,rw, read/write privilege to the group path",
			},
			"path": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Path in the target group to which access will be granted. Start with the groupname",
			},
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the source group that will be granted access",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: grantObject.grantGroupAccess,
		},
	}
}

func pathGrantAWSAccess(b *backend) *framework.Path {
	grantObject := &GrantMeta{
        configobj: createConfigObject(b),
    }   
	return &framework.Path{
		Pattern: "grant/access/aws",
		Fields: map[string]*framework.FieldSchema{
			"privilege": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:	"r",
				Description: "r,w,rw, read/write privilege to the group path",
			},
			"path": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "group path in the groups_secrets to share",
			},
			"role_arn": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "ARN of the AWS role that will acess the path.",
			},
			"ttl": &framework.FieldSchema{
				Type:		framework.TypeString,
				Default:	"0.5h",
				Description: "TTL for the token your role use.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: grantObject.grantAWSRole,
		},
	}
}

func pathGrantKubernetesAccess(b *backend) *framework.Path {
	grantObject := &GrantMeta{
        configobj: createConfigObject(b),
    }   
	return &framework.Path{
		Pattern: "grant/access/kubernetes",
		Fields: map[string]*framework.FieldSchema{
			"path": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "group path in the groups_secrets to share",
			},
			"privilege": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:	"r",
				Description: "r,w,rw, read/write privilege to the group path",
			},
			"service_account_name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "",
				Description: "Service Account Name.",
			},
			"service_account_namespace": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "",
				Description: "Service Account Name namespace.",
			},
			"ttl": &framework.FieldSchema{
				Type:		framework.TypeString,
				Default:	"0.5h",
				Description: "TTL for the token your role use.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: grantObject.grantKubernetesRole,
		},
	}
}

func (b *GrantMeta) grantGroupServerCert(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.grantServerCert(ctx,req,data,"groups","add")
}
func (b *GrantMeta) revokeGroupServerCert(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.grantServerCert(ctx,req,data,"groups","remove")
}

func (b *GrantMeta) grantAWSServerCert(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.grantServerCert(ctx,req,data,"aws","add")
}

func (b *GrantMeta) grantServerCert(ctx context.Context, req *logical.Request, data *framework.FieldData,authtype,action string) (*logical.Response, error) {
	granteename := data.Get("name").(string)
	configEntry, err := b.configobj.readConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}
	c := &ClientMeta{
		ClientToken: configEntry.RootToken,
	}
	if(authtype=="groups") {
		groupInfo, err := c.read("/v1/identity/group/name/" + granteename)
		if(groupInfo == nil || err !=nil){
			return logical.ErrorResponse(granteename + " should be  registered first "), err
		}
	} else {
		res, err := c.readID(authtype, "role", granteename)
		if  res == nil {
			return logical.ErrorResponse(granteename + " should be  registered first "), err
		}
	}
	body := map[string]string{
		"path": "auth/exchange/cert/server/*" ,
		"privilege" : "e",
		"target" : "certs",
		"grant_type" : "execute",
		"authtype" : authtype,
		"granteename" : granteename,
		"policy_name" : authtype + "-" +granteename,
		"groupname" : configEntry.AdminGroup,
	}
	return c.updateGrantPolicy(configEntry,body,action)
}


func (b *GrantMeta) grantGroupAccess(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	granteename := data.Get("name").(string)
	body,err := b.readParams(ctx,req,data,"groups",granteename)
	if err !=nil {
		return logical.ErrorResponse("failed to readParams"), err
	}
	configEntry, err := b.configobj.readConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}

	c := &ClientMeta{
		ClientToken: configEntry.RootToken,
	}
	return c.updateGrantPolicy(configEntry,body,"add")
}

func (b *GrantMeta) grantKubernetesRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	granteename := data.Get("role").(string)
	bound_service_account_names := data.Get("service_account_name").(string)
	bound_service_account_namespaces := data.Get("service_account_namespace").(string)
	body := map[string]string{
		"bound_service_account_names": bound_service_account_names,
		"bound_service_account_namespaces": bound_service_account_namespaces,
	}
	return b.grantRole(ctx, req,  data , "kubernetes", granteename, body)
}

func (b *GrantMeta) grantAWSRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role := data.Get("role").(string)
	granteename := createUniqueRoleNameFromARN(role)
	body := map[string]string{
		"bound_iam_principal_arn": role,
		"auth_type":               "iam",
	}
	return b.grantRole(ctx, req,  data , "aws", granteename, body)
}

func (b *GrantMeta) grantRole(ctx context.Context,req *logical.Request,  data *framework.FieldData, authtype, granteename string, roleObject map[string]string ) (*logical.Response, error) {
	body,err := b.readParams(ctx,req,data,authtype,granteename)
	if err !=nil {
		return logical.ErrorResponse("failed to readParams"), err
	}
	configEntry, err := b.configobj.readConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}

	c := &ClientMeta{
		ClientToken: configEntry.RootToken,
	}
	res, err := c.readID(authtype, "role", granteename)
	if  res == nil {
		roleObject["policies"]=body["policy_name"]
		err= c.writeID(authtype, "role", granteename ,roleObject)
    	if err != nil {
			return logical.ErrorResponse("Failed to create AWS Role ID in Vault for  "+ granteename  +", " + err.Error()), errors.New("Failed to create AWS Role ID in Vault for  " +granteename + ", " + err.Error())
		}
	}
	return c.updateGrantPolicy(configEntry,body,"add")
}

func (b *GrantMeta) readParams(ctx  context.Context,req *logical.Request, data *framework.FieldData, authtype,granteename string ) (map[string]string,error) {
	body := map[string]string{
		"path": data.Get("path").(string),
		"privilege" : data.Get("privilege").(string),
		"authtype" :authtype,
		"granteename" :granteename,
		"grant_type" : "path",
		"policy_name" : authtype + "-" +granteename,
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
	body["target"]=groupname

    groupObject := &groupMeta{
        configobj: b.configobj,
    }
	found,err:=groupObject.checkIfMyGroup(ctx,req,body["groupname"])
	if err !=nil {
		return nil, err
	}
	if found==false {
		return nil, errors.New("You can only grant acces to  a group that you belong to you")
	}
	//trace.Println("Vault-Exchange PLUGIN TRACE -> GrantMeta->grant->","readParams-> ",body)
	return body,nil
}

func createUniqueRoleNameFromARN(arn string) string {
	return strings.Split(strings.Split(arn, "::")[1], ":")[0] + "_" + strings.Split(arn, "/")[1]
}
 

//authtype=kubernetes,aws,kubernetes,groups
func (c *ClientMeta) updateGrantPolicy(configEntry *configData,body map[string]string,action string) (*logical.Response, error)  {
	path:=body["path"]
	authtype:=body["authtype"]
	privilege:=body["privilege"]
	granteename:=body["granteename"]
	groupname:=body["groupname"]
	target:=body["target"]
	grant_type:=body["grant_type"]
	policy_name:=body["policy_name"]

	val, err := c.updateGrantMetadata("/v1/"+configEntry.RootPath+"/secret/metadata/grant/source/"+authtype+"/"+granteename, "policy" ,action, path,privilege)
	if err !=nil {
		return logical.ErrorResponse("Failed to update metadata for " + granteename+ ", " + err.Error()), errors.New("Failed  to update metadata for  " + granteename+ ", " + err.Error())
	}
	_, err = c.updateGrantMetadata("/v1/"+configEntry.RootPath+"/secret/metadata/grant/target/"+grant_type +"/"+target, "policy" ,action, granteename+":"+path,privilege)
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
	executepaths :=strings.Split(val.e,";")
	for i:=0;i<len(executepaths) ;i++ {
		if len(executepaths[i])>1 {
			policystr = policystr+ "\npath \""+  executepaths[i] +"\" { capabilities = [\"update\"]}\n"
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
	var val GRANT_PATHS
	val.r=updateOneMetaPathKey(metadata,"r", action, path,privilege )
	val.w=updateOneMetaPathKey(metadata,"w", action, path,privilege )
	val.e=updateOneMetaPathKey(metadata,"e", action, path,privilege )
	return  val,c.write(metapath,metadata)
}

func updateOneMetaPathKey(metadata map[string]string, key, action, path,privilege string) (string)  {
	val, ok := metadata[key]
	if  ok {
		if strings.Contains(privilege,key) {
			val=strings.ReplaceAll(val,path+";","")
		} 
	} else {
		val=""
	}

	if action=="add" {
		if strings.Contains(privilege,key) {
			val= path+";"+val
		}
	}
	metadata[key]=val
	return val
}

