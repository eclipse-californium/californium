#!/bin/bash

#/*******************************************************************************
# * Copyright (c) 2024 Contributors to the Eclipse Foundation.
# * 
# * See the NOTICE file(s) distributed with this work for additional
# * information regarding copyright ownership.
# * 
# * This program and the accompanying materials
# * are made available under the terms of the Eclipse Public License v2.0
# * and Eclipse Distribution License v1.0 which accompany this distribution.
# * 
# * The Eclipse Public License is available at
# *    http://www.eclipse.org/legal/epl-v20.html
# * and the Eclipse Distribution License is available at
# *    http://www.eclipse.org/org/documents/edl-v10.html.
# * 
# * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
# * 
# ******************************************************************************/

KEY_STORE=keyStore.p12
KEY_STORE_PWD=endPass

DEFAULT_STORE_TYPE=PKCS12

# CSR & CER 
ROOT_CER=root.cer
SERVER_CER=server.cer
CLIENT_CER=client.cer


# PEM 
SERVER_KEY_STORE_PEM=server.pem
CLIENT_KEY_STORE_PEM=client.pem

SERVER_KEY_STORE_P12=server.p12
CLIENT_KEY_STORE_P12=client.p12

VALIDITY=730


create_keys() {
   echo "creating root key and certificate..."
   keytool -genkeypair -alias root -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-root' \
        -ext BC=ca:true -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD -storetype $DEFAULT_STORE_TYPE
   keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias root | \
      keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -alias root -gencert -validity $VALIDITY -ext BC=ca:true -ext KU=keyCertSign,cRLSign -sigalg SHA256withECDSA -rfc > $ROOT_CER
   keytool -alias root -noprompt -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -file $ROOT_CER -storetype $DEFAULT_STORE_TYPE

   echo "creating server key and certificate..."
   keytool -genkeypair -alias server -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-cloud-server' \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD -storetype $DEFAULT_STORE_TYPE
   keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias server | \
      keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -alias root -gencert -ext KU=dig \
      -ext 'san=dns:my.coap.server,ip:8.9.10.11' \
      -validity $VALIDITY -sigalg SHA256withECDSA -rfc > $SERVER_CER
   keytool -alias server -noprompt -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file $SERVER_CER -storetype $DEFAULT_STORE_TYPE

   echo "creating client key and certificate..."
   keytool -genkeypair -alias client -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client' \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD -storetype $DEFAULT_STORE_TYPE
   keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias client | \
        keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -alias root -gencert -ext KU=dig \
        -validity $VALIDITY -sigalg SHA256withECDSA -rfc > $CLIENT_CER
   keytool -alias client -noprompt -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file $CLIENT_CER
}

export_p12() {
   if [ -z "$LEGACY" ]  ; then
      echo "exporting keys into PKCS#12 format"
   else
      echo "exporting keys into PKCS#12 format to support android (legacy encryption)"
   fi	
   keytool $LEGACY -v -importkeystore -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD -alias client \
      -destkeystore $CLIENT_KEY_STORE_P12 -deststorepass $KEY_STORE_PWD -deststoretype PKCS12
   keytool $LEGACY -v -importkeystore -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD -alias server \
      -destkeystore $SERVER_KEY_STORE_P12 -deststorepass $KEY_STORE_PWD -deststoretype PKCS12

}

export_pem() {
   openssl version

   if [ $? -eq 0 ] ; then
      echo "exporting keys into PEM format"
      openssl pkcs12 -in $SERVER_KEY_STORE_P12 -passin pass:$KEY_STORE_PWD -nodes -out $SERVER_KEY_STORE_PEM
      openssl pkcs12 -in $CLIENT_KEY_STORE_P12 -passin pass:$KEY_STORE_PWD -nodes -out $CLIENT_KEY_STORE_PEM     
   else 
      echo "missing openssl, no pem credentials are exported."
   fi
} 

create_client_keys() {

   echo "creating client-$1 key and certificate..."
   keytool -genkeypair -alias client-$1 -keyalg EC -dname "C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client-$1" \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD -storetype $DEFAULT_STORE_TYPE
   keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias client-$1 | \
        keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -alias root -gencert -ext KU=dig \
        -validity $VALIDITY -sigalg SHA256withECDSA -rfc > $CLIENT_CER
   keytool -alias client-$1 -noprompt -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file $CLIENT_CER
}

export_client_pem() {
   keytool -v -importkeystore -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD -alias client-$1 \
      -destkeystore client-$1.p12 -deststorepass $KEY_STORE_PWD -deststoretype PKCS12

   openssl version

   if [ $? -eq 0 ] ; then
      echo "exporting client-$1 keys into PEM format"
      openssl pkcs12 -in client-$1.p12 -passin pass:$KEY_STORE_PWD -nodes -out client-$1.pem     
   else 
      echo "missing openssl, no pem credentials are exported."
   fi
}

import_server_keys() { 
   echo "creating server certificate from keys (privkey.pem) ..."
   openssl x509 -new -SHA256 -key privkey.pem -days $VALIDITY -subj '/C=CA/L=Ottawa/O=Eclipse IoT/OU=Californium/CN=cf-server/' -out servercert.pem
   openssl pkcs12 -export -in servercert.pem -inkey privkey.pem -out serverImport.p12 -name server2 -passout pass:$KEY_STORE_PWD
        
   echo "import server certificate ..."
   keytool -alias server2 -noprompt -importkeystore -destkeystore $KEY_STORE -deststorepass $KEY_STORE_PWD -srckeystore serverImport.p12 -srcstorepass $KEY_STORE_PWD

   echo "sign server certificate ..."
   keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias server2 | \
      keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -alias root -gencert -ext KU=dig \
      -ext 'san=dns:my.coap.server,ip:8.9.10.11' \
      -validity $VALIDITY -sigalg SHA256withECDSA -rfc > $SERVER2_CER
   echo "import signed server certificate ..."
   keytool -alias server2 -noprompt -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file $SERVER2_CER
}

export_server2_pem() {
   keytool -v -importkeystore -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD -alias server2 \
      -destkeystore server2.p12 -deststorepass $KEY_STORE_PWD -deststoretype PKCS12

   openssl version

   if [ $? -eq 0 ] ; then
      echo "exporting server2 keys into PEM format"
      openssl pkcs12 -in server2.p12 -passin pass:$KEY_STORE_PWD -nodes -out server2.pem     
   else 
      echo "missing openssl, no pem credentials are exported."
   fi
}


jobs () {
  while [ -n "$1" ]
  do
    echo "$1"
    case $1 in
      "create")
        create_keys
	;;
      "export")
        export_p12
        export_pem
	;;
      "create-client")
	shift
        create_client_keys $1
        export_client_pem $1
	;;
      "export-client")
	shift
        export_client_pem $1
	;;
      "import-server2")
        import_server_keys
	;;
      "export-server2")
        export_server2_pem
	;;
    esac
    shift
  done
}

if [ -z "$1" ]  ; then
     echo "default: create export"
     JOBS="create export"
else 
     JOBS=$@	
fi

jobs ${JOBS}

