A major security weakness in most organizations is the process of sharing secrets between users. People use all kinds of insecure channels to pass passwords, keys, tokens etc. Vault can be extended to provide a secure service for exchanging secrets between individuals.

# vault-exchange
Vault Exchange adds delegation capabilities to HashiCorp Vault enabling it to be used as a key exchange service between users.  
**This code is a POC to demonstrate basic delegation capabilities using an Auth Plugin.**

## Setup
You must have a Vault server already running, unsealed, and authenticated. The code has been tested with **userpass** and **ldap**      authentication but it can be modified to work with any other auth method

1. Compile the plugin and move it into Vault's configured `plugin_directory`:

  ```sh
  $ mv vault-exchange $vault_dir/plugins/
  ```

1. Calculate the SHA256 of the plugin and register it in Vault's plugin catalog.

  ```sh
  $ export SHA256=$(shasum -a 256 "$vault_dir/plugins/vault-exchange" | cut -d' ' -f1)

  $ vault write sys/plugins/catalog/vault-exchange  sha_256="${SHA256}" command="vault-exchange"
  ```

1. Enable the plugin

  ```sh
  $ vault auth enable -path=exchange  -plugin-name=vault-exchange plugin
  ```

## Configure the plugin 
You need to provide the following arguments while configuring the plugin
* **token** Admin token ($admintoken)
* **path** Root path for the organization to store secrets. This path gets appended to "secret" 
* **auth** Authentication Type 
* **debug** Trace level for logging 

```sh
$ vault write auth/exchange/config  display_name=exchange auth=$auth_type path=$root_path token=$roottoken
e.g
$ vault write vault write auth/exchange/config  display_name=exchange auth=ldap path=mycompany/myorg token=$roottoken debug=1
```
## Register users or groups with vault
This step creates a user/group in the configured authentication path as well as a policy that gives the user/group all access to their home path(  secret/$root_path/$username/*)
* **user** Users login name ($username)
```sh
$ vault write auth/exchange/register  type=groups/users name=$groupname/$username
```
**Note:** Register is an authenticated call. So effectively users need to login first and then register



## Grant and revoke access to a user on a given path
* **token** User token ($usertoken)
* **user** This is the target username   
* **path** Target path in the users home where the secrets to be shared are stored. Read access  to this path is granted or revoked ($home_path/$target_path)

```sh
$ vault write auth/exchange/command/grant user=$targetuser  path=$target_path token=$usertoken

$ vault write auth/exchange/command/revoke  user=$targetuser   path=$target_path token=$usertoken
```
## Summary
Users register with vault using their username (from their authentication credentials). Since the registration path is authenticated, it needs user to login first and it allows user to register their login name as well as ldap groups name with vault. During the registration process the plugin creates a home path for the users/groups where they can store their secrets, it also creates an authorization policy for them which allows them access to this path. 
Once users are registered they can login to vault. This results in a token being generated that is needed for the grant/revoke commands. When they want to share a secret with other users they use the **grant** command to delegate the read privilege to the target user for their secrets. Under the covers the plugin updates the target users authorization policy and adds the path to the secrets.



## Issues
There is a bug in the plugin framework that results in the **logical.Request.EntityID** being empty instead of containing 
*the identity of the caller extracted out of the token used to make this request* (https://godoc.org/github.com/hashicorp/vault/logical#Request) . If this gets resolved then there should not be a need to pass user token in the grant/revoke calls  


