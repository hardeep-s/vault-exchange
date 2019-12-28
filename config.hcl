storage "file" {
  path = "vault/data"
}

listener "tcp" {
  address = "localhost:8200"
  tls_disable = 0
  tls_cert_file = "certs/localhost.crt"
  tls_key_file = "certs/localhost.key"
}

plugin_directory = "vault/plugin"
disable_mlock = true
api_addr = "https://localhost:8200"
ui = true
