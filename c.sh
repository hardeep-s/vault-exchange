#!/bin/sh
# Initialize server
#set -x
VAULT_PATH=~/Workspace/bin/vault
VAULT_ADDR='https://localhost:8200'
AWS_SM_ARN=arn:aws:secretsmanager:us-east-1:903664935542:secret:ec2/vault/prod/infosec-8juA1H
if [ -z "$2" ] ; then
	echo "create total-key minimum-to-unseal"
	exit 0
fi
if [ $1 -lt 6 ] || [ $2 -lt 2 ]; then
	echo "atleast 6  total-key and 2 minimum-to-unseal are required"
	exit 0
fi
if [ $1 -lt $2 ]; then
	echo "total-key cannot be less than  minimum-to-unseal"
	exit 0
fi
export VAULT_SKIP_VERIFY=true
secrets=$(aws secretsmanager get-secret-value --secret-id $AWS_SM_ARN --query SecretString --output text )
if [ -z "$secrets" ] ; then
	echo "Cannot access AWS Secrets "
	exit 0
fi
OIDC_CLIENT_SECRET=$(echo $secrets | jq -r  .OIDC_CLIENT_SECRET)
OIDC_CLIENT_ID=$(echo $secrets | jq -r  .OIDC_CLIENT_ID)
OIDC_API_TOKEN=$(echo $secrets | jq -r  .OIDC_API_TOKEN)
OIDC_API_URL=$(echo $secrets | jq -r .OIDC_API_URL)
OIDC_ENDPOINT=$(echo $secrets | jq -r .OIDC_ENDPOINT)
CN=$(echo $secrets | jq -r  .CN)
VAULT_ADMIN=$(echo $secrets | jq -r .VAULT_ADMIN)
DOMAIN=$(echo $secrets | jq -r .DOMAIN)


echo export CLIENT_SECRET=$OIDC_CLIENT_SECRET
echo export CLIENT_ID=$OIDC_CLIENT_ID
echo export API_TOKEN=$OIDC_API_TOKEN
echo export API_URL=$OIDC_API_URL
echo export ENDPOINT=$OIDC_ENDPOINT
echo export CN=$CN
echo export VAULT_ADMIN=$VAULT_ADMIN
echo export DOMAIN=$DOMAIN
var=$($VAULT_PATH  operator init -key-shares=$1 -key-threshold=$2  -format "json" )
echo $var > /tmp/vault.init 
#var=$(cat  /tmp/vault.init)
if [ -z "$var" ] 
then
  echo "Unseal the vault using the existing keys"
else	
	ROOT_TOKEN=$(echo $var | jq -r  .root_token)
	admintoken=$ROOT_TOKEN
	keys=$(echo $var | jq  .unseal_keys_hex[] )

	COUNTER=1
	for key in $(echo "${var}" | jq -r '.unseal_keys_hex[]'); do
    	if [ $COUNTER -le $2 ]; then
			$VAULT_PATH operator unseal ${key} 
		fi
    	COUNTER=$((COUNTER + 1))
	done
fi
$VAULT_PATH login $ROOT_TOKEN
$VAULT_PATH secrets enable -version=1 kv
$VAULT_PATH policy write default  default_policy.hcl

#$VAULT_PATH auth disable oidc
$VAULT_PATH auth enable oidc


$VAULT_PATH  write auth/oidc/config oidc_discovery_url=$OIDC_ENDPOINT oidc_client_id=$OIDC_CLIENT_ID oidc_client_secret=$OIDC_CLIENT_SECRET default_role="okta"
$VAULT_PATH write auth/oidc/role/onelogin bound_audiences="$OIDC_CLIENT_ID" allowed_redirect_uris="$VAULT_ADDR/ui/vault/auth/oidc/oidc/callback" user_claim="preferred_username" groups_claim="groups" oidc_scopes="groups"  policies="default"
$VAULT_PATH write auth/oidc/config oidc_discovery_url=$OIDC_ENDPOINT oidc_client_id=$OIDC_CLIENT_ID oidc_client_secret=$OIDC_CLIENT_SECRET default_role="okta"
$VAULT_PATH write auth/oidc/role/okta -<<EOF
{
"user_claim": "name",
"bound_audiences": ["api://vault","$OIDC_CLIENT_ID"],
"allowed_redirect_uris": "https://localhost:8200/ui/vault/auth/oidc/oidc/callback",
"role_type": "oidc",
"oidc_scopes": ["profile","openid"],
"groups_claim" : "groups",
"policies": "default"
}
EOF

# ******************* Setup PKI ************************
$VAULT_PATH  secrets enable -path=upstart-client pki
$VAULT_PATH  secrets tune -max-lease-ttl=8760h upstart-client
$VAULT_PATH write upstart-client/root/generate/internal common_name=$DOMAIN ttl=8760h
$VAULT_PATH write upstart-client/config/urls issuing_certificates="https://localhost:8200/v1/upstart-client/ca" crl_distribution_points="https://localhost:8200/v1/upstart-client/crl"
$VAULT_PATH write upstart-client/roles/issuecerts allow_any_name=true allowed_domains=$DOMAIN allow_subdomains=true max_ttl=24h client_flag=true server_flag=false

$VAULT_PATH  secrets enable -path=upstart-server pki
$VAULT_PATH  secrets tune -max-lease-ttl=8760h upstart-server
$VAULT_PATH write upstart-server/root/generate/internal common_name=$DOMAIN ttl=8760h
$VAULT_PATH write upstart-server/config/urls issuing_certificates="https://localhost:8200/v1/upstart-server/ca" crl_distribution_points="https://localhost:8200/v1/upstart-server/crl"
$VAULT_PATH write upstart-server/roles/issuecerts  allowed_domains=$DOMAIN allow_subdomains=true max_ttl=8760h client_flag=false server_flag=true

# ******************* Setup AWS *******************************
$VAULT_PATH auth enable aws
$VAULT_PATH write auth/aws/config/client iam_server_id_header_value=$DOMAIN

# ******************* Setup Kubernetes *******************************
$VAULT_PATH auth enable kubernetes

# ******************* Setup Plugin ************************
export SHA256=$(shasum -a 256 vault/plugin/vault-exchange | cut -d' ' -f1)
#$VAULT_PATH auth disable exchange
$VAULT_PATH write sys/plugins/catalog/vault-exchange  sha_256="${SHA256}" command="vault-exchange"
$VAULT_PATH auth enable -path=exchange  -plugin-name=vault-exchange plugin
$VAULT_PATH write auth/exchange/setup display_name=exchange root_path=kv root_token=$admintoken  admin_group="$VAULT_ADMIN" client_certs_pki="upstart-client" server_certs_pki="upstart-server"  certs_cn=$CN certs_role="issuecerts"
$VAULT_PATH write auth/exchange/authz/config api_token=$OIDC_API_TOKEN api_url=$OIDC_API_URL

echo "******** DONE**************"
exit 0
