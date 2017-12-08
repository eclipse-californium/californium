#!/bin/bash

KEY_STORE=keyStore.jks
KEY_STORE_PWD=endPass
TRUST_STORE=trustStore.jks
TRUST_STORE_PWD=rootPass

# android support
KEY_STORE_P12=keyStore.p12
TRUST_STORE_P12=trustStore.p12

VALIDITY=365

echo "creating root key and certificate..."
keytool -genkeypair -alias root -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-root' \
        -ext BC=ca:true -validity $VALIDITY -keypass $TRUST_STORE_PWD -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD

echo "creating CA key and certificate..."
keytool -genkeypair -alias ca -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-ca' \
        -ext BC=ca:true -validity $VALIDITY -keypass $TRUST_STORE_PWD -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD
keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -certreq -alias ca | \
  keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias root -gencert -validity $VALIDITY -ext BC=0 -rfc | \
  keytool -alias ca -importcert -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD

echo "creating server key and certificate..."
keytool -genkeypair -alias server -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server' \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias server | \
  keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias ca -gencert -ext KU=dig -validity $VALIDITY -rfc > server.pem
keytool -alias server -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file server.pem

echo "creating client key and certificate..."
keytool -genkeypair -alias client -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client' \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias client | \
  keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias ca -gencert -ext KU=dig -validity $VALIDITY -rfc > client.pem
keytool -alias client -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file client.pem

echo "exporting keys into PKCS#12 format to support android"
keytool -v -importkeystore -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD \
   -destkeystore $KEY_STORE_P12 -deststorepass $KEY_STORE_PWD -deststoretype PKCS12
keytool -v -importkeystore -srckeystore $TRUST_STORE -srcstorepass $TRUST_STORE_PWD \
   -destkeystore $TRUST_STORE_P12 -deststorepass $TRUST_STORE_PWD -deststoretype PKCS12
