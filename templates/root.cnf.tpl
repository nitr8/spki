[ req ]
default_bits        = {{ROOT_KEY_BITS}}
default_md          = sha256
prompt              = no
distinguished_name  = dn
x509_extensions     = v3_root_ca
string_mask         = utf8only

[ dn ]
C  = {{COUNTRY}}
ST = {{STATE}}
L  = {{LOCALITY}}
O  = {{ORG}}
OU = {{ORG_UNIT}}
CN = {{ROOT_CA_CN}}

[ v3_root_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:1
keyUsage               = critical, keyCertSign, cRLSign
