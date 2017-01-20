#!/bin/bash

KEY_STORE=keyStore.jks
KEY_STORE_PWD=endPass
TRUST_STORE=trustStore.jks
TRUST_STORE_PWD=rootPass
NO_TRUST_STORE=noTrustStore.jks
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

echo "creating alien root key and certificate for trust failure ..."
keytool -genkeypair -alias root -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=alien-root' \
        -ext BC=ca:true -validity $VALIDITY -keypass $TRUST_STORE_PWD -keystore $NO_TRUST_STORE -storepass $TRUST_STORE_PWD

echo "creating server key and certificate..."
keytool -genkeypair -alias server -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server' \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias server | \
  keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias ca -gencert -validity $VALIDITY -rfc > server.pem
keytool -alias server -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file server.pem

echo "creating client key and certificate..."
keytool -genkeypair -alias client -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client' \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias client | \
  keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias ca -gencert -validity $VALIDITY -rfc > client.pem
keytool -alias client -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file client.pem


