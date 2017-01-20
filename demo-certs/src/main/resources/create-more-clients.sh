#!/bin/bash

KEY_STORE=keyStore.jks
KEY_STORE_PWD=endPass
TRUST_STORE=trustStore.jks
TRUST_STORE_PWD=rootPass
VALIDITY=365

function createclient {
	echo "creating client $1 keys and certificates..."
	keytool -genkeypair -alias client-$1 -keyalg EC -dname "C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client-$1" \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
	keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias client-$1 | \
        keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias ca -gencert -validity $VALIDITY -rfc > client-$1.pem
	keytool -alias client-$1 -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file client-$1.pem
}

echo "creating more client keys and certificates..."
for i in `seq 1 9`;
do
	createclient $i
done 