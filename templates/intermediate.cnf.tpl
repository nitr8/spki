[ req ]
default_bits        = {{INTERMEDIATE_KEY_BITS}}
default_md          = sha256
prompt              = no
distinguished_name  = dn
string_mask         = utf8only

[ dn ]
C  = {{COUNTRY}}
ST = {{STATE}}
L  = {{LOCALITY}}
O  = {{ORG}}
OU = {{ORG_UNIT}}
CN = {{INTERMEDIATE_CA_CN}}

[ v3_intermediate_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
