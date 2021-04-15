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
			"arn": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "AWS Role ARN mapped to the Role name  ",
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

		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: roleobj.registerAWSRole,
		},
	}
}

func (roleobj *roleMeta) registerAWSRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rolename := data.Get("name").(string)
	arn := data.Get("arn").(string)
	configEntry, err := roleobj.configobj.readConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}
	c := &ClientMeta{
		ClientToken: configEntry.RootToken,
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
		return logical.ErrorResponse("You can only register a group that you belong to "), errors.New("You can only register a group that you belong to")
	}
	res, err := c.readID("aws", "role", rolename)
	if  res != nil {
		return logical.ErrorResponse("Role " + rolename + " is already  registered"), errors.New("Role " + rolename + "is already registered")
	}
	ttl:=data.Get("ttl").(string)
    ttlValue, err := time.ParseDuration(ttl)
    if err != nil {
        return logical.ErrorResponse("Invalid TTL"), err
    } else if ttlValue > MAXTTL {
            return nil, errors.New("Maximum value of ttl can be  "+MAXTTL.String()+ " hours")
    }
	role_policy_name := "role-" +  rolename
	body := map[string]string{
        "policies":                role_policy_name,
        "bound_iam_principal_arn": arn,
        "auth_type":               "iam",
        "ttl":                     ttl,
    }
    err= c.writeID("aws" , "role" , rolename, body)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}
    metadata:= make(map[string]string)
	metadata["admin_group"]=groupname
	metadata["arn"]=arn
	metadata["policy_name"]=role_policy_name
	metadata["account"] = strings.Split(strings.Split(arn, "::")[1], ":")[0]
	c.write("/v1/"+configEntry.RootPath+"/secret/metadata/roles/aws/"+rolename,metadata)

	role_policy, err := c.createPolicy(configEntry, "roles", rolename, "admin",role_policy_name,"*")
	if err != nil {
			return logical.ErrorResponse("Failed to create a policy for " + rolename+ ", " + err.Error()), err
	}
	return c.writePolicy(role_policy_name, role_policy)
}

func (roleobj *roleMeta) unRegisterRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rolename := data.Get("name").(string)
	configEntry, err := roleobj.configobj.readConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}
	c := &ClientMeta{
		ClientToken: configEntry.RootToken,
	}
	res, err := c.readID("aws", "role", rolename)
	if  res == nil {
		return logical.ErrorResponse("Role " + rolename + " is not  registered"), errors.New("Role " + rolename + "is not registered")
	}
	result, err := c.read("/v1/"+configEntry.RootPath+"/secret/metadata/roles/aws/"+rolename)
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
	err= c.deleteID("aws", "role",rolename )
	if err != nil {
		return logical.ErrorResponse("Failed to delete  ID for" + rolename), err
	}
	return nil,nil
}

