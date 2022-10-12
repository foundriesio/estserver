#!/bin/sh 
## Helper for creating a TLS keypair for your EST server that is signed by
## your factory root CA.

set -e

if [ $# -ne 3 ] ; then
    echo "Usage: $0 <factory-name> <dns-name> <pki-dir>"
    echo "Example: $0 demo-factory demo-factory.example.com /secrets/factory-pki"
    exit 0
fi
factory=$1
dnsname=$2
pkidir=$3

[ -f ${pkidir}/factory_ca.key ] || (echo "ERROR: pki-dir missing factory_ca.key"; exit 1)

tmpdir=$(mktemp -d)
trap "rm -rf $tmpdir" SIGINT SIGTERM ERR EXIT

keyfile=${tmpdir}/${dnsname}.key
certfile=${tmpdir}/${dnsname}.pem
csrfile=${tmpdir}/${dnsname}.csr

conf=${tmpdir}/tmp.cnf
cat > $conf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = est-server
OU = $factory

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $dnsname
EOF

# Create CSR
openssl ecparam -genkey -name prime256v1 | openssl ec -out ${keyfile}
openssl req -new -config ${conf} -key ${keyfile} -out ${csrfile}

# Sign it
dns=$(openssl req -text -noout -verify -in $csrfile | grep DNS:)
echo "signing with dns name: $dns" 1>&2
cat >${tmpdir}/server.ext <<EOF
keyUsage=critical, digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage=critical, serverAuth
subjectAltName=$dns
EOF
openssl x509 -req -days 3650 -in ${csrfile} -CAcreateserial -extfile ${tmpdir}/server.ext \
    -CAkey ${pkidir}/factory_ca.key -CA ${pkidir}/factory_ca.pem > ${certfile}

# Save it
mv ${certfile} ${keyfile} ${pkidir}/
echo Key pair at: ${pkidir}/${dnsname}.key and ${dnsname}.pem