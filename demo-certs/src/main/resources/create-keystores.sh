#!/bin/bash

KEY_STORE=keyStore.jks
KEY_STORE_PWD=endPass
TRUST_STORE=trustStore.jks
TRUST_STORE_PWD=rootPass

# CSR & CER 
ROOT_CER=root.cer
CA_CER=ca.cer
CA2_CER=ca2.cer
CA_RSA_CER=caRsa.cer
SERVER_CER=server.cer
SERVER_LARGE_CER=serverLarge.cer
SERVER_RSA_CER=serverRsa.cer
CLIENT_CER=client.cer
CLIENT_EXT_CER=clientExt.cer

# android support - PKCS12
TRUST_STORE_P12=trustStore.p12
CA_TRUST_STORE_P12=caTrustStore.p12
CA_RSA_TRUST_STORE_P12=caRsaTrustStore.p12
CLIENT_KEY_STORE_P12=client.p12
SERVER_KEY_STORE_P12=server.p12
SERVER_LARGE_KEY_STORE_P12=serverLarge.p12
SERVER_RSA_KEY_STORE_P12=serverRsa.p12

# PEM 
TRUST_STORE_PEM=trustStore.pem
CA_TRUST_STORE_PEM=caTrustStore.pem
CA_RSA_TRUST_STORE_PEM=caRsaTrustStore.pem
CLIENT_KEY_STORE_PEM=client.pem
SERVER_KEY_STORE_PEM=server.pem
SERVER_LARGE_KEY_STORE_PEM=serverLarge.pem
SERVER_RSA_KEY_STORE_PEM=serverRsa.pem
EC_PUBLIC_KEY_PEM=ec_public.pem
EC_PRIVATE_KEY_PEM=ec_private.pem

VALIDITY=365

remove_keys() {
	rm -f $KEY_STORE $TRUST_STORE
	rm -f $ROOT_CER $CA_CER $CA2_CER $CA_RSA_CER $SERVER_CER $SERVER_LARGE_CER $SERVER_RSA_CER $CLIENT_CER $CLIENT_EXT_CER
	rm -f $CLIENT_KEY_STORE_P12 $SERVER_KEY_STORE_P12 $SERVER_LARGE_KEY_STORE_P12 $SERVER_RSA_KEY_STORE_P12 $TRUST_STORE_P12 $CA_TRUST_STORE_P12 $CA_RSA_TRUST_STORE_P12
	rm -f $CLIENT_KEY_STORE_PEM $SERVER_KEY_STORE_PEM $SERVER_LARGE_KEY_STORE_PEM $SERVER_RSA_KEY_STORE_PEM $TRUST_STORE_PEM $EC_PUBLIC_KEY_PEM $EC_PRIVATE_KEY_PEM $CA_TRUST_STORE_PEM $CA_RSA_TRUST_STORE_PEM
}

create_keys() {
   echo "creating root key and certificate..."
   keytool -genkeypair -alias root -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-root' \
        -ext BC=ca:true -validity $VALIDITY -keypass $TRUST_STORE_PWD -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD
   keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -certreq -alias root | \
      keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias root -gencert -validity $VALIDITY -ext BC=ca:true -rfc > $ROOT_CER
   keytool -alias root -importcert -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -file $ROOT_CER

   echo "creating CA key and certificate..."
   keytool -genkeypair -alias ca -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-ca' \
        -ext BC=1 -validity $VALIDITY -keypass $TRUST_STORE_PWD -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD
   keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -certreq -alias ca | \
      keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias root -gencert -validity $VALIDITY -ext BC=1 -ext KU=keyCertSign,cRLSign -rfc > $CA_CER
   keytool -alias ca -importcert -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -file $CA_CER

   echo "creating server key and certificate..."
   keytool -genkeypair -alias server -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server' \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
   keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias server | \
      keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias ca -gencert -ext KU=dig -validity $VALIDITY -rfc > $SERVER_CER
   keytool -alias server -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file $SERVER_CER

   echo "creating CA2 key and certificate..."
   keytool -genkeypair -alias ca2 -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-ca2' \
        -ext BC=0 -validity $VALIDITY -keypass $TRUST_STORE_PWD -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD
   keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -certreq -alias ca2 | \
      keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias ca -gencert -validity $VALIDITY -ext BC=0 -ext KU=keyCertSign,cRLSign -rfc > $CA2_CER
   keytool -alias ca2 -importcert -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -file $CA2_CER

   echo "creating serverlarge key and certificate..."
   keytool -genkeypair -alias serverlarge -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-serverlarge' \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
   keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias serverlarge | \
      keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias ca2 -gencert -ext KU=dig -validity $VALIDITY -rfc > $SERVER_LARGE_CER
   keytool -alias serverlarge -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file $SERVER_LARGE_CER

   echo "creating CA RSA key and certificate..."
   keytool -genkeypair -alias carsa -keyalg RSA -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-ca-rsa' \
        -ext BC=0 -validity $VALIDITY -keypass $TRUST_STORE_PWD -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD
   keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -certreq -alias carsa | \
      keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias root -gencert -validity $VALIDITY -ext BC=0 -ext KU=keyCertSign,cRLSign -rfc > $CA_RSA_CER
   keytool -alias carsa -importcert -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -file $CA_RSA_CER

   echo "creating server key with ca-rsa and certificate..."
   keytool -genkeypair -alias serverrsa -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server-rsa' \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
   keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias serverrsa | \
      keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias carsa -gencert -ext KU=dig -validity $VALIDITY -rfc > $SERVER_RSA_CER
   keytool -alias serverrsa -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file $SERVER_RSA_CER

   echo "creating client key and certificate..."
   keytool -genkeypair -alias client -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client' \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
   keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias client | \
      keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias ca -gencert -ext KU=dig -validity $VALIDITY -rfc > $CLIENT_CER
   keytool -alias client -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file $CLIENT_CER

   echo "creating self-signed key and certificate..."
   keytool -genkeypair -alias self -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-self' \
        -ext BC=ca:true -ext KU=keyCertSign -ext KU=dig -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD

   echo "creating certificate with no digitalSignature keyusage..."
   keytool -genkeypair -alias nosigning -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-nosigning' \
        -ext BC=ca:true -ext KU=keyEn -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD

   echo "creating client key and certificate with extended keyusage..."
   keytool -genkeypair -alias clientext -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-clientext' \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
   keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias clientext | \
      keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias ca -gencert -ext KU=dig -ext EKU=clientAuth -validity $VALIDITY -rfc > $CLIENT_EXT_CER
   # the keytool supports two modes of certificates import
   # - import a certificate chain (as it is)
   # - import a certificate (and amend the chain from the CA certificates in the store)
   # gencert creates a chain excluding the top-level self-signed root-certificate from that chain
   # importing a single signed certificate amend also this top-level self-signed roo-tcertificate to that chain
   # to test the behaviour for certificate chains including the top-level self-signed root-certificate, amend it to the chain generated by gencert 
   cat $ROOT_CER >> $CLIENT_EXT_CER  
   keytool -alias clientext -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file $CLIENT_EXT_CER

}

export_p12() {
   echo "exporting keys into PKCS#12 format to support android"
   keytool -v -importkeystore -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD -alias client \
      -destkeystore $CLIENT_KEY_STORE_P12 -deststorepass $KEY_STORE_PWD -deststoretype PKCS12
   keytool -v -importkeystore -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD -alias server \
      -destkeystore $SERVER_KEY_STORE_P12 -deststorepass $KEY_STORE_PWD -deststoretype PKCS12
   keytool -v -importkeystore -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD -alias serverlarge \
      -destkeystore $SERVER_LARGE_KEY_STORE_P12 -deststorepass $KEY_STORE_PWD -deststoretype PKCS12
   keytool -v -importkeystore -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD -alias serverrsa \
      -destkeystore $SERVER_RSA_KEY_STORE_P12 -deststorepass $KEY_STORE_PWD -deststoretype PKCS12
   keytool -v -importkeystore -srckeystore $TRUST_STORE -srcstorepass $TRUST_STORE_PWD -alias ca \
      -destkeystore $CA_TRUST_STORE_P12 -deststorepass $TRUST_STORE_PWD -deststoretype PKCS12
   keytool -v -importkeystore -srckeystore $TRUST_STORE -srcstorepass $TRUST_STORE_PWD -alias carsa \
      -destkeystore $CA_RSA_TRUST_STORE_P12 -deststorepass $TRUST_STORE_PWD -deststoretype PKCS12
   keytool -v -importkeystore -srckeystore $TRUST_STORE -srcstorepass $TRUST_STORE_PWD \
      -destkeystore $TRUST_STORE_P12 -deststorepass $TRUST_STORE_PWD -deststoretype PKCS12
}

export_pem() {
   openssl version

   if [ $? -eq 0 ] ; then
      echo "exporting keys into PEM format"
      openssl pkcs12 -in $SERVER_KEY_STORE_P12 -passin pass:$KEY_STORE_PWD -nodes -out $SERVER_KEY_STORE_PEM
      openssl pkcs12 -in $SERVER_LARGE_KEY_STORE_P12 -passin pass:$KEY_STORE_PWD -nodes -out $SERVER_LARGE_KEY_STORE_PEM
      openssl pkcs12 -in $SERVER_RSA_KEY_STORE_P12 -passin pass:$KEY_STORE_PWD -nodes -out $SERVER_RSA_KEY_STORE_PEM
      openssl pkcs12 -in $CLIENT_KEY_STORE_P12 -passin pass:$KEY_STORE_PWD -nodes -out $CLIENT_KEY_STORE_PEM
      openssl pkcs12 -in $CA_TRUST_STORE_P12 -passin pass:$TRUST_STORE_PWD -nokeys -out $CA_TRUST_STORE_PEM
      openssl pkcs12 -in $CA_RSA_TRUST_STORE_P12 -passin pass:$TRUST_STORE_PWD -nokeys -out $CA_RSA_TRUST_STORE_PEM
      openssl pkcs12 -in $TRUST_STORE_P12 -passin pass:$TRUST_STORE_PWD -nokeys -out $TRUST_STORE_PEM
      openssl ecparam -genkey -name prime256v1 -noout -out $EC_PRIVATE_KEY_PEM
      openssl ec -in ec_private.pem -pubout -out $EC_PUBLIC_KEY_PEM
   fi
} 

jobs () {
  echo "$1"
  case $1 in
     "remove")
        remove_keys
	;;
     "create")
        create_keys
	;;
     "export")
        export_p12
        export_pem
	;;
  esac
}

if [ -z "$1" ]  ; then
     echo "default: remove create export"
     JOBS="remove create export"
else 
     JOBS=$@	
fi

for JOB in ${JOBS}; do
   jobs ${JOB}
done
