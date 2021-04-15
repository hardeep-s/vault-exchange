package main

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"context"
	"errors"
	"strings"
	"time"
)



type roleMeta struct {
    configobj *configMeta
}


func pathRegisterKubernetesRole(b *backend) *framework.Path {
	roleobj := &roleMeta{
        configobj: createConfigObject(b),
    }   
	return &framework.Path{
		Pattern: "register/kubernetes",
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Role name to register",
			},
			"group": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Group that will act as the administrator for the role",
			},
			"ttl": &framework.FieldSchema{
				Type:		framework.TypeString,
				Default:	"0.5h",
				Description: "TTL for the token your role use.",
			},
			"namespace": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Kubernetes Namespace",
			},
			"service_account": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "name of the kubernetes service account",
			},

		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: roleobj.registerKubernetesRole,
		},
	}
}

func pathRegisterAWSRole(b *backend) *framework.Path {
	roleobj := &roleMeta{
        configobj: createConfigObject(b),
    }   
	return &framework.Path{
		Pattern: "register/aws",
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Role name to register",
			},
			"group": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Group that will act as the administrator for the role",
			},
			"ttl": &framework.FieldSchema{
				Type:		framework.TypeString,
				Default:	"0.5h",
				Description: "TTL for the token your role use.",
			},
			"arn": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "AWS Role ARN mapped to the Role name  ",
			},

		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: roleobj.registerAWSRole,
		},
	}
}
func (roleobj *roleMeta) registerAWSRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return roleobj.registerRole(ctx,req,data,"aws")
}
func (roleobj *roleMeta) registerKubernetesRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return roleobj.registerRole(ctx,req,data,"kubernetes")
}



func (roleobj *roleMeta) registerRole(ctx context.Context, req *logical.Request, data *framework.FieldData,authtype string) (*logical.Response, error) {
	configEntry, err := roleobj.configobj.readConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}
	c := &ClientMeta{
		ClientToken: configEntry.RootToken,
	}

	ttl:=data.Get("ttl").(string)
    ttlValue, err := time.ParseDuration(ttl)
    if err != nil {
        return logical.ErrorResponse("Invalid TTL"), err
    } else if ttlValue > MAXTTL {
            return nil, errors.New("Maximum value of ttl can be  "+MAXTTL.String()+ " hours")
    }
	groupname := data.Get("group").(string)
    if groupname == "" {
		return logical.ErrorResponse("You need to provide a group that will administrator the role "), errors.New("You need to provide a group that will administrator the role ")
	}

	groupobj := &groupMeta{
        configobj: roleobj.configobj,
    }   
	found,err:=groupobj.checkIfMyGroup(ctx,req,groupname)
	if err !=nil {
		return logical.ErrorResponse("Error while fetching group info "), err
	}
	if found==false {
		return logical.ErrorResponse("You can only assign a group that you belong to "), errors.New("You can only assign a group that you belong to")
	}

	body := map[string]string{
        "ttl": ttl,
    }
    metadata:= map[string]string {
		"admin_group":groupname,
	}

	if authtype=="aws" {
		arn:=data.Get("arn").(string)
    	if arn == "" {
			return logical.ErrorResponse("Role ARN missing "), errors.New("Role ARN missing " )
		}
		body["bound_iam_principal_arn"]=arn
		body["auth_type"]="iam"
		metadata["account"] = strings.Split(strings.Split(arn, "::")[1], ":")[0]
		metadata["name"] = authtype+"-"+metadata["account"] +"-"+strings.Split(arn, "/")[1]
		metadata["arn"]=arn
	} else {
		namespace:=data.Get("namespace").(string)
    	if namespace == "" {
			return logical.ErrorResponse("namespace missing "), errors.New("Namespace missing " )
		}
		service_account:=data.Get("service_account").(string)
    	if service_account == "" {
			return logical.ErrorResponse("service_acount missing "), errors.New("Service Account missing  ")
		}
		body["bound_service_account_names"]=service_account
		body["bound_service_account_namespaces"]=namespace
		metadata["name"] = authtype+"-"+namespace
		metadata["service_account"] = service_account
	}
	body["policies"]=metadata["name"]

	res, err := c.readID(authtype, "role", metadata["name"])
	if  res != nil {
		return logical.ErrorResponse("Role " + metadata["name"] + " is already  registered"), errors.New("Role " + metadata["name"] + "is already registered")
	}

	c.writeSecret(configEntry,authtype,metadata["name"]+"/secrets/donot_remove","Do not remove this key val")
	c.write("/v1/"+configEntry.RootPath+"/secret/metadata/config/"+authtype+"/"+metadata["name"],metadata)

	role_policy, err := c.createPolicy(configEntry, authtype, metadata["name"], "admin",body["policies"],"*")
	if err != nil {
			return logical.ErrorResponse("Failed to create a policy for " + metadata["name"]+ ", " + err.Error()), err
	}
	return c.writePolicy(body["policies"], role_policy)
}

func (roleobj *roleMeta) unRegisterRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rolename := data.Get("name").(string)
	configEntry, err := roleobj.configobj.readConfig(ctx, req)
	authtype:="aws"
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}
	c := &ClientMeta{
		ClientToken: configEntry.RootToken,
	}
	res, err := c.readID(authtype, "role", rolename)
	if  res == nil {
		return logical.ErrorResponse("Role " + rolename + " is not  registered"), errors.New("Role " + rolename + "is not registered")
	}
	result, err := c.read("/v1/"+configEntry.RootPath+"/secret/metadata/config/"+authtype+"/"+rolename)
    if err != nil {
		return logical.ErrorResponse("Could not fetch metadata for  " + rolename ), errors.New("Could not fetch metadata for  " + rolename)
	}
	metadata,ok:=result["data"].(map[string]string)
	if !ok {
		return logical.ErrorResponse("Could not read metadata for  " + rolename ), errors.New("Could not read metadata for  " + rolename)
	}
	role_policy_name := metadata["policy_name"]
	groupname := metadata["admin_group"]
	groupobj := &groupMeta{
        configobj: roleobj.configobj,
    }   
	found,err:=groupobj.checkIfMyGroup(ctx,req,groupname)
	if err !=nil {
		return logical.ErrorResponse("Error while fetching group info "), err
	}
	if found==false {
		return logical.ErrorResponse("You are not a member of the admin group for this role"), errors.New("You are not a member of the admin group for this role")
	}

	err = c.deletePolicy(role_policy_name)
	if err != nil {
		return logical.ErrorResponse("Failed to delete the policy for role " + rolename), err
	}
	err= c.deleteID(authtype, "role",rolename )
	if err != nil {
		return logical.ErrorResponse("Failed to delete  ID for" + rolename), err
	}
	return nil,nil
}

