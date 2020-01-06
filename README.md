A major security weakness in most devops is the storage and use of secrets at deployment and runtime. Secrets are stored in config files on the server, on operators laptops, in GIT and so on. Vault can be extended to provide a secure service for storing secrets so that they can be loaded by services at runtime. This also has an added benefits of consolidating and creating an inventory of secrets for the service as well as the ability to rotate the secrets at any time.
The main problem with this approach is that vault requires an administrator to create the policies to enable a service as well as the service operators to access the path where the secrets are stored. In affect the administrator needs to manage the access control for every user and service in the organization. This approach has a scalability problem


# vault-exchange
Vault Exchange adds self-management capabilities to HashiCorp Vault enabling it to be used as a secret store for service secrets without requiring an administrator. The exchange achieves this by allowing any authenticated user to add an OIDC group to vault. The policy associated with the OIDC group allows all members of the groups (including services) to access the group path to read and write secrets.

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
* **path** Secret engine path 

```sh
$ vault write auth/exchange/config  display_name=exchange  path=$kv_path token=$roottoken
e.g
$ vault write vault write auth/exchange/config  display_name=exchange  path=kv token=$roottoken 
```
## Register  groups with vault
This step creates a group in the configured authentication path as well as a policy that gives the group all access to their home path()
* **user** Users login name ($username)
```sh
$ vault write auth/exchange/register   name=$groupname
```
**Note:** Register is an authenticated call. So effectively users need to login first and then register

## Summary
Vault exchange enables Vault to be run as a self-service secret repository that leverages LDAP group membership to enable services to dynamically load secrets from a secure source at runtime.


