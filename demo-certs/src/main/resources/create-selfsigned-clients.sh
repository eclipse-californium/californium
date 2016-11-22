#!/bin/bash

KEY_STORE=selfSignedKeyStore.jks
KEY_STORE_PWD=selfPass
VALIDITY=365

function createclient {
	echo "creating self-signed client $1 keys and certificates..."
	keytool -genkeypair -alias cf-self-signed-client-$1 -keyalg EC -dname "C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-self-signed-client-$1" \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
}

echo "creating self signed client keys and certificates..."
for i in `seq 1 9`;
do
	createclient $i
done 

echo "creating self signed server key and certificate..."
keytool -genkeypair -alias cf-self-signed-server -keyalg EC -dname "C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-self-signed-server" \
    -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
