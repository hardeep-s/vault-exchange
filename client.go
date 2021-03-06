package main

import (
	"bytes"
	"errors"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/logical"
	"net/http"
    "io/ioutil"
	"text/template"
	//"runtime/debug"
)


type Policy struct {
	RootPath, Idtype, Name, Path, ServerCertPath, ClientCertPath string
}
const super_admin_policy = `
path "{{.ServerCertPath}}/*" {capabilities = ["read","update","delete"]}
path "{{.ClientCertPath}}/*" {capabilities = ["read","update","delete"]}
path "auth/exchange/*" {capabilities = ["read","update","delete","list"]}
path "sys/policy/*" {capabilities = ["list","read"]}
path "identity/*" {capabilities = ["list","read"]}
path "{{.RootPath}}/*" {capabilities = ["list","read"]}
path "{{.RootPath}}/secret/data/{{.Idtype}}/{{.Name}}/secrets/{{.Path}}" { capabilities = ["list", "create", "read", "update","delete", "sudo"]}
`

const group_admin_policy = `
path "auth/exchange" {capabilities = ["read","update","delete","list"]}
path "auth/exchange/cert" {capabilities = ["read","update","delete","list"]}
path "auth/exchange/cert/client" {capabilities = ["read","update","delete","list"]}
path "auth/exchange/cert/client/*" {capabilities = ["update"]}
path "auth/exchange/grant" {capabilities = ["update"]}
path "auth/exchange/grant/access" {capabilities = ["update"]}
path "auth/exchange/grant/access/*" {capabilities = ["update"]}
path "{{.RootPath}}" { capabilities = ["list" ]}
path "{{.RootPath}}/secret" { capabilities = ["list" ]}
path "{{.RootPath}}/secret/data" { capabilities = ["list" ]}
path "{{.RootPath}}/secret/data/{{.Idtype}}" { capabilities = ["list"]}
path "{{.RootPath}}/secret/data/{{.Idtype}}/{{.Name}}" { capabilities = ["list"]}
path "{{.RootPath}}/secret/data/{{.Idtype}}/{{.Name}}/secrets" { capabilities = ["list"]}
path "{{.RootPath}}/secret/data/{{.Idtype}}/{{.Name}}/secrets/{{.Path}}" { capabilities = ["list", "create", "read", "update","delete", "sudo"]}
`

const grant_read_only_policy = `
path "{{.RootPath}}/secret/data/{{.Idtype}}" { capabilities = ["list"]}
path "{{.RootPath}}/secret/data/{{.Idtype}}/{{.Name}}" { capabilities = ["list"]}
path "{{.RootPath}}/secret/data/{{.Idtype}}/{{.Name}}/secrets" { capabilities = ["list"]}
path "{{.RootPath}}/secret/data/{{.Idtype}}/{{.Name}}/secrets/{{.Path}}" { capabilities = ["list","read"]}
`
 
const grant_write_only_policy = `
path "{{.RootPath}}/secret/data/{{.Idtype}}" { capabilities = ["list"]}
path "{{.RootPath}}/secret/data/{{.Idtype}}/{{.Name}}" { capabilities = ["list"]}
path "{{.RootPath}}/secret/data/{{.Idtype}}/{{.Name}}/secrets" { capabilities = ["list"]}
path "{{.RootPath}}/secret/data/{{.Idtype}}/{{.Name}}/secrets/{{.Path}}" { capabilities = ["list","update"]}
`

const grant_read_write_policy = `
path "{{.RootPath}}/secret/data/{{.Idtype}}" { capabilities = ["list"]}
path "{{.RootPath}}/secret/data/{{.Idtype}}/{{.Name}}" { capabilities = ["list"]}
path "{{.RootPath}}/secret/data/{{.Idtype}}/{{.Name}}/secrets" { capabilities = ["list"]}
path "{{.RootPath}}/secret/data/{{.Idtype}}/{{.Name}}/secrets/{{.Path}}" { capabilities = ["list","read","update"]}
`

type ClientMeta struct {
	ClientToken string
}

 

// Init a client 
func (c *ClientMeta) Client() (*api.Client, error) {
	config := api.DefaultConfig()
	client, err := api.NewClient(config)
	if err == nil {
		client.SetToken(c.ClientToken)
	}
	return client, err
}

//read contents from an external URL
// CMD="GET","PUT","POST"
func (c *ClientMeta) REST(cmd,url,token string,  body []byte) ([] byte, error) {
    req, err := http.NewRequest(cmd, url, bytes.NewBuffer(body))
    if err != nil {
		trace.Println("Vault-Exchange PLUGIN TRACE ->Client-> REST-> ",err)
		return nil,err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	if token !="" {
	    req.Header.Add("Authorization", token)
	}
	if body!= nil {
	    req.Header.Add("Content-Length", string(len(body)))
	}

    client := &http.Client{}
	/*
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
        for key, val := range via[0].Header {
            req.Header[key] = val
		trace.Println("Vault-Exchange PLUGIN TRACE ->FFFFFFFFFFFFFFFFF ",key,"=",val)
        }
        return err
    }
	*/
    resp, err := client.Do(req)
    if err != nil {
		trace.Println("Vault-Exchange PLUGIN TRACE ->Client-> REST-> ",err)
		return nil,err
    } else {
        defer resp.Body.Close()
        return  ioutil.ReadAll(resp.Body)
    }
}

//read contents from a path
func (c *ClientMeta) read(path string) (map[string]interface{}, error) {
	client, err := c.Client()
	if err != nil {
		trace.Println("Vault-Exchange PLUGIN TRACE ->Client-> read-> ",err)
		return nil, err
	}

	r := client.NewRequest("GET", path)
	resp, err := client.RawRequest(r)
	if resp != nil {
		defer resp.Body.Close()
		if resp.StatusCode == 404 {
			return nil, errors.New("Response->404->"+path)
		}
	}
	if err != nil {
		//debug.PrintStack()
		trace.Println("Vault-Exchange PLUGIN TRACE ->Client-> read-> ",err)
		return nil, err
	}

	var result map[string]interface{}
	err = resp.DecodeJSON(&result)
	return result, nil
}

//write contents to a path
func (c *ClientMeta) write(path string, body map[string]string) error {
	_,err:= c.writeCmd("PUT",path , body )
	return err;
}
func (c *ClientMeta) writeCmd(cmd,path string, body map[string]string) (map[string]interface{}, error)  {
	client, err := c.Client()
	if err == nil {
		r := client.NewRequest(cmd, path)
		err = r.SetJSONBody(body)
		if err == nil {
			resp, _ := client.RawRequest(r)
			if resp != nil {
				defer resp.Body.Close()
				if resp.StatusCode == 404 {
					trace.Println("Vault-Exchange PLUGIN TRACE ->Client-> writeCmd->Response->404",r.URL,resp.Body)
					return nil, nil
				}
			}
			defer resp.Body.Close()
			var result map[string]interface{}
			err = resp.DecodeJSON(&result)
			return result, nil
		}
	}
	return nil,err
}

func (c *ClientMeta) delete(path string) error {
	client, err := c.Client()
	if err != nil {
		trace.Println("Vault-Exchange PLUGIN TRACE ->Client-> delete-> ",err)
		return err
	}
	r := client.NewRequest("DELETE", path)
	resp, err := client.RawRequest(r)
	if err != nil {
		trace.Println("Vault-Exchange PLUGIN TRACE ->Client-> delete->RawRequest ",err)
		return err
	}
	if resp != nil {
		defer resp.Body.Close()
	}
	return err
}

//authtype=kubernetes,aws,oidc
//idtype=role,group
func (c *ClientMeta) readID(authtype, idtype, name string) (interface{}, error) {
	result, err := c.read("/v1/auth/" + authtype + "/" + idtype + "/" + name)
	if err != nil {
		trace.Println("Vault-Exchange PLUGIN TRACE ->Client-> readID-> ",err)
		return nil, err
	}
	if policyRaw, ok := result["data"]; ok {
		return policyRaw, nil
	}
	return nil, errors.New("Error while reading ID for "+name )

}

//authtype=kubernetes,aws,oidc
//idtype=role,group
func (c *ClientMeta) writeID(authtype, idtype, name string,body  map[string]string) error {
	/*
	body := map[string]string{
		"policies": policy,
	}
	*/
	return c.write("/v1/auth/"+authtype+"/"+idtype+"/"+name, body)
}

func (c *ClientMeta) deleteID(authtype, idtype, name string) error {
	return c.delete("/v1/auth/" + authtype +  "/" + idtype + "/" + name)
}

func (c *ClientMeta) readToken() (interface{}, error) {
	result, err := c.read("/v1/auth/token/lookup-self")
	if err != nil {
		return nil, err
	}
	if policyRaw, ok := result["data"]; ok {
		return policyRaw, nil
	}
	return nil, errors.New("error read token data")

}

func (c *ClientMeta) writeSecret(configEntry *configData,authtype,path,comments string) error {
 	keyval := map[string]string{
        "comments": comments,
    }
	rrr:=c.write("/v1/"+configEntry.RootPath+"/secret/data/"+authtype+"/"+path, keyval)
	return rrr;
}

//idtype==groups,aws,kubernetes
func (c *ClientMeta) createPolicy(configEntry *configData, idtype, name, privileges,policy_name,path string, ) (string, error) {
	policyMetaData := Policy{
		RootPath: configEntry.RootPath,
		ServerCertPath: configEntry.ServerCertPath,
		ClientCertPath: configEntry.ClientCertPath,
		Idtype: idtype,
		Name: name,
		Path: path,
	}
	policyData, err := template.New(policy_name).Parse(grant_read_only_policy)
	if privileges=="su" {
		policyData, err = template.New(policy_name).Parse(super_admin_policy)
	} else if privileges=="admin" {
		policyData, err = template.New(policy_name).Parse(group_admin_policy)
	} else {
		policyData, err = template.New(policy_name).Parse(grant_write_only_policy)
	}
	if err != nil {
		return "", err
	}
	var policyObject bytes.Buffer
	err = template.Must(policyData, err).Execute(&policyObject, policyMetaData)
	if err != nil {
		return "", err
	}
	return policyObject.String(), nil
}

//write a policy to Vault
func (c *ClientMeta) writePolicy(name, rules string) (*logical.Response, error) {
	client, err := c.Client()
	if err != nil {
		return logical.ErrorResponse("writePolicy->failed io open client"), err
	}
	//trace.Println("Vault-Exchange PLUGIN TRACE ->client ","writePolicy-> ", name, rules)
	if err := client.Sys().PutPolicy(name, rules); err != nil {
		return logical.ErrorResponse("writePolicy->failed to  write policy"), err
	}
	return nil, nil
}

func (c *ClientMeta) deletePolicy(name string) error {
	return	c.delete("/v1/sys/policy/"+name)
}


func (c *ClientMeta) listPolicies() (interface{}, error) {
	path := "/v1/sys/policy"
	result, err := c.read(path)
	if err != nil {
		return nil, err
	}
	if policyRaw, ok := result["data"]; ok {
		return policyRaw, nil
	} 
	return nil, errors.New("error listing policies")
}
