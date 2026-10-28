[ req ]
default_bits        = {{SERVER_KEY_BITS}}
default_md          = sha256
prompt              = no
distinguished_name  = dn
req_extensions      = v3_req
string_mask         = utf8only

[ dn ]
C  = {{COUNTRY}}
ST = {{STATE}}
L  = {{LOCALITY}}
O  = {{ORG}}
OU = {{ORG_UNIT}}
CN = {{FQDN}}

[ v3_req ]
subjectKeyIdentifier   = hash
basicConstraints       = critical, CA:false
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = @alt_names

[ alt_names ]
{{ALT_NAMES}}
