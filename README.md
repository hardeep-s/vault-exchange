# vault-exchange
Vault Exchange adds delegation capabilities to HashiCorp Vault in order to use it as a key exchange service between users.  
It can also be used as an example for building a Vault auth plugin.
**This code is a POC to demonstrate basic delegation capabilities using an Auth Plugin. Do not use it in production.**

## Setup

You must have a Vault server already running, unsealed, and authenticated. The code has been tested with **userpass** authentication but it can be modified to work with any other auth method

1. Compile the plugin and move it into Vault's configured `plugin_directory`:

  ```sh
  $ mv vault-exchange $vault_dir/plugins/
  ```

1. Calculate the SHA256 of the plugin and register it in Vault's plugin catalog.

  ```sh
  $ export SHA256=$(shasum -a 256 "$vault_dir/plugins/vault-exchange" | cut -d' ' -f1)

  $ vault write sys/plugins/catalog/vault-exchange  sha_256="${SHA256}" command="vault-exchange"
  ```

1. Mount the auth method:

  ```sh
  $ vault auth-enable -path=exchange  -plugin-name=vault-exchange plugin
  ```

## Configure the plugin 
You need to provide the following arguments while configuring the plugin
* **token** Admin token ($admintoken)
* **path** Home path for the users secrets $secrets_sub_path. This path get appended to "secret" 
* **debug** Trace level for logging 

```sh
$ vault write auth/exchange/config  display_name=exchange path=$secrets_sub_path token=$admintoken
e.g
$ vault write vault write auth/exchange/config  display_name=exchange path=cpe/keys token=$admintoken debug=1
```
## Register users with vault
This step creates a policy that gives the user all access to secret/$secrets_sub_path/$username/*
* **token** User token ($usertoken)
```sh
$ vault write auth/exchange/register  token=$usertoken
```

## Grant and revoke access to a user on a given path
* **token** User token ($usertoken)
* **user** This is the username that is used by the target user for authentication   
* **path** Read access is given/revoked to the target user to this path (secret/$secrets_sub_path/$granters_username/$secrets_for_targetuser)

```sh
$ vault write auth/exchange/command/grant user=$targetuser  path=$secrets_for_targetuser token=$usertoken

$ vault write auth/exchange/command/revoke  user=$targetuser   path=$secrets_for_targetuser token=$usertoken
```
## Summary
The user authenticate with vault and gets a token. First time users use this token to register with the plugin.
Since vault separates authentication from authorization any one can authenticate with Vault can then do self authorization to a fixed home path. Once they register the plugin creates a home path for them where they can create and manage their secrets, it also creates an authorization policy for them which allows them access to this path as well as delegation command to the plugin. When they want to share a secret with another user they use the grant command to delegate the read privilege to the target  user for the secrets path. Under the covers the plugin updates the target users authorization policy and adds the secrets path to it



## Issues
There is a bug in the plugin framework that results in the logical.Request.EntityID being empty instead of containing 
*the identity of the caller extracted out of the token used to make this request* (https://godoc.org/github.com/hashicorp/vault/logical#Request) . If this gets resolved then there should not be a need to pass user token in the grant/revoke calls  


