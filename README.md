# vault-exchange
Vault Exchange adds delegaion capibilties to HashiCorp Vault in order to use it as a key exchange service between users.  
It can also be used as an example for building a Vault auth plugin.

**This code is a POC to demonstrate basic delegation capibilites using an Auth Plugin. Do not use it in production.**

## Setup

You must have a Vault server already running, unsealed, and authenticated. The code has been tested with userpass authentication but it can be modified to work with any other auth method

1. Compile the plugine and move it into Vault's configured `plugin_directory`:

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
*token: Admin token ($admintoken)
*path: Home path for the users secrets $secrets_sub_path. This path get appended to "secret" 
*debug: Trace level for logging 

```sh
$ vault write auth/exchange/config  display_name=exchange path=$secrets_sub_path token=$admintoken
e.g
$ vault write vault write auth/exchange/config  display_name=exchange path=cpe/keys token=$admintoken debug=1
```

