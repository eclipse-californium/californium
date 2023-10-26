#!/bin/bash

#/*******************************************************************************
# * Copyright (c) 2016-2020 Bosch.IO GmbH and others.
# * 
# * All rights reserved. This program and the accompanying materials
# * are made available under the terms of the Eclipse Public License v2.0
# * and Eclipse Distribution License v1.0 which accompany this distribution.
# * 
# * The Eclipse Public License is available at
# *    http://www.eclipse.org/legal/epl-v20.html
# * and the Eclipse Distribution License is available at
# *    http://www.eclipse.org/org/documents/edl-v10.html.
# * 
# * Contributors:
# *    Bosch.IO GmbH - initial script
# ******************************************************************************/
#
# Requires:
#   java keytool
#
# Optional (some (interoperability- and unit-tests may not work without)
#   openssl, docker
#
# Note:
#
# EdDSA requires java 15 (or newer)
# sudo update-java-alternatives -s java-1.15.0-openjdk-amd64
#
# For usage with java 16, see
# https://www.oracle.com/java/technologies/javase/16-relnotes.html#JDK-8153005
# 
# If the p12 keystore is intended to be used by legacy JDK (7,8,11) the stronger
# encryption must be disabled. Comment the line with LEGACY, if stronge encryption
# should be applied and the p12 keystore is not used by legacy JDKs. 
#
LEGACY=-J-Dkeystore.pkcs12.legacy

KEY_STORE=keyStore.jks
KEY_STORE_PWD=endPass
TRUST_STORE=trustStore.jks
TRUST_STORE_PWD=rootPass

# to prevent java 11 from failing to open the other jks
EDDSA_KEY_STORE=eddsaKeyStore.jks
EDDSA_TRUST_STORE=eddsaTrustStore.jks

DEFAULT_STORE_TYPE=JKS

# CSR & CER 
ROOT_CER=root.cer
CA_CER=ca.cer
CA2_CER=ca2.cer
CA_RSA_CER=caRsa.cer
CA_EDDSA_CER=caEdDsa.cer
SERVER_CER=server.cer
SERVER_LARGE_CER=serverLarge.cer
SERVER_RSA_CER=serverRsa.cer
SERVER_CA_RSA_CER=serverCaRsa.cer
SERVER_EDDSA_CER=serverEdDsa.cer
CLIENT_CER=client.cer
CLIENT_EXT_CER=clientExt.cer
CLIENT_EDDSA_CER=clientEdDsa.cer
CLIENT_RSA_CER=clientRsa.cer
CLIENT_EXPIRED_CER=clientExpired.cer

# android support - PKCS12
TRUST_STORE_P12=trustStore.p12
EDDSA_TRUST_STORE_P12=eddsaTrustStore.p12
CA_TRUST_STORE_P12=caTrustStore.p12
CA_RSA_TRUST_STORE_P12=caRsaTrustStore.p12
CA_EDDSA_TRUST_STORE_P12=caEdDsaTrustStore.p12
CLIENT_KEY_STORE_P12=client.p12
CLIENT_EDDSA_KEY_STORE_P12=clientEdDsa.p12
CLIENT_RSA_KEY_STORE_P12=clientRsa.p12
SERVER_KEY_STORE_P12=server.p12
SERVER_LARGE_KEY_STORE_P12=serverLarge.p12
SERVER_RSA_KEY_STORE_P12=serverRsa.p12
SERVER_CA_RSA_KEY_STORE_P12=serverCaRsa.p12
SERVER_EDDSA_KEY_STORE_P12=serverEdDsa.p12
ROOT_TRUST_STORE_P12=rootTrustStore.p12

# PEM 
TRUST_STORE_PEM=trustStore.pem
EDDSA_TRUST_STORE_PEM=eddsaTrustStore.pem
ROOT_TRUST_STORE_PEM=rootTrustStore.pem
CA_TRUST_STORE_PEM=caTrustStore.pem
CA_RSA_TRUST_STORE_PEM=caRsaTrustStore.pem
CA_EDDSA_TRUST_STORE_PEM=caEdDsaTrustStore.pem
CLIENT_KEY_STORE_PEM=client.pem
CLIENT_EDDSA_KEY_STORE_PEM=clientEdDsa.pem
CLIENT_RSA_KEY_STORE_PEM=clientRsa.pem
SERVER_KEY_STORE_PEM=server.pem
SERVER_LARGE_KEY_STORE_PEM=serverLarge.pem
SERVER_RSA_KEY_STORE_PEM=serverRsa.pem
SERVER_CA_RSA_KEY_STORE_PEM=serverCaRsa.pem
SERVER_EDDSA_KEY_STORE_PEM=serverEdDsa.pem
EC_PUBLIC_KEY_PEM=ec_public.pem
EC_PRIVATE_KEY_PEM=ec_private.pem
ED25519_PUBLIC_KEY_PEM=ed25519_public.pem
ED25519_PRIVATE_KEY_PEM=ed25519_private.pem
ED448_PUBLIC_KEY_PEM=ed448_public.pem
ED448_PRIVATE_KEY_PEM=ed448_private.pem

CLIENT_PRIVATE_KEY_PEM=clientPrivateKey.pem
CLIENT_RSA_PRIVATE_KEY_PEM=clientRsaPrivateKey.pem
SERVER_PRIVATE_KEY_PEM=serverPrivateKey.pem
SERVER_RSA_PRIVATE_KEY_PEM=serverRsaPrivateKey.pem
SERVER_CA_RSA_PRIVATE_KEY_PEM=serverCaRsaPrivateKey.pem

CLIENT_KEY_STORE_DER=client.der
TRUST_STORE_DER=trustStore.der

VALIDITY=730

remove_keys() {
	rm -f $KEY_STORE $TRUST_STORE $EDDSA_KEY_STORE $EDDSA_TRUST_STORE
	rm -f $ROOT_CER $CA_CER $CA2_CER $CA_RSA_CER $SERVER_CER $SERVER_LARGE_CER $SERVER_RSA_CER $SERVER_CA_RSA_CER $CLIENT_CER $CLIENT_EXT_CER $CLIENT_EDDSA_CER $CLIENT_RSA_CER $SERVER_EDDSA_CER $CA_EDDSA_CER $CLIENT_EXPIRED_CER
	rm -f $CLIENT_KEY_STORE_P12 $SERVER_KEY_STORE_P12 $SERVER_LARGE_KEY_STORE_P12 $SERVER_RSA_KEY_STORE_P12 $SERVER_CA_RSA_KEY_STORE_P12 $SERVER_RSA_KEY_STORE_P12 $TRUST_STORE_P12 $CA_TRUST_STORE_P12 $CA_RSA_TRUST_STORE_P12 $CLIENT_EDDSA_KEY_STORE_P12 $CLIENT_RSA_KEY_STORE_P12 $ROOT_TRUST_STORE_P12 $SERVER_EDDSA_KEY_STORE_P12 $CA_EDDSA_TRUST_STORE_P12 $EDDSA_TRUST_STORE_P12
	rm -f $CLIENT_KEY_STORE_PEM $SERVER_KEY_STORE_PEM $SERVER_LARGE_KEY_STORE_PEM $SERVER_RSA_KEY_STORE_PEM $SERVER_CA_RSA_KEY_STORE_PEM $TRUST_STORE_PEM $CA_TRUST_STORE_PEM $CA_RSA_TRUST_STORE_PEM $CLIENT_EDDSA_KEY_STORE_PEM $CLIENT_RSA_KEY_STORE_PEM $ROOT_TRUST_STORE_PEM $SERVER_EDDSA_KEY_STORE_PEM $CA_EDDSA_TRUST_STORE_PEM
	rm -f $EC_PUBLIC_KEY_PEM $EC_PRIVATE_KEY_PEM $ED25519_PUBLIC_KEY_PEM $ED25519_PRIVATE_KEY_PEM $ED448_PUBLIC_KEY_PEM $ED448_PRIVATE_KEY_PEM
	rm -f $CLIENT_PRIVATE_KEY_PEM $CLIENT_RSA_PRIVATE_KEY_PEM $SERVER_PRIVATE_KEY_PEM $SERVER_RSA_PRIVATE_KEY_PEM $SERVER_CA_RSA_PRIVATE_KEY_PEM
}

remove_interop_keys() {
  echo "remove keys from californium-interoperability-tests"
  DESTINATION_DIR=../../californium-tests/californium-interoperability-tests
  rm -f ${DESTINATION_DIR}/$TRUST_STORE_PEM
  rm -f ${DESTINATION_DIR}/$ROOT_TRUST_STORE_PEM
  rm -f ${DESTINATION_DIR}/$CA_TRUST_STORE_PEM
  rm -f ${DESTINATION_DIR}/$CA_RSA_TRUST_STORE_PEM 
  rm -f ${DESTINATION_DIR}/$CA_EDDSA_TRUST_STORE_PEM 
  rm -f ${DESTINATION_DIR}/$EDDSA_TRUST_STORE_PEM 
  rm -f ${DESTINATION_DIR}/$CLIENT_KEY_STORE_PEM 
  rm -f ${DESTINATION_DIR}/$CLIENT_EDDSA_KEY_STORE_PEM
  rm -f ${DESTINATION_DIR}/$CLIENT_RSA_KEY_STORE_PEM
  rm -f ${DESTINATION_DIR}/$SERVER_KEY_STORE_PEM 
  rm -f ${DESTINATION_DIR}/$SERVER_LARGE_KEY_STORE_PEM 
  rm -f ${DESTINATION_DIR}/$SERVER_RSA_KEY_STORE_PEM 
  rm -f ${DESTINATION_DIR}/$SERVER_CA_RSA_KEY_STORE_PEM
  rm -f ${DESTINATION_DIR}/$SERVER_EDDSA_KEY_STORE_PEM 
  rm -f ${DESTINATION_DIR}/$EC_PRIVATE_KEY_PEM
  # gnutls keys
  rm -f ${DESTINATION_DIR}/$CLIENT_PRIVATE_KEY_PEM
  rm -f ${DESTINATION_DIR}/$CLIENT_RSA_PRIVATE_KEY_PEM
  rm -f ${DESTINATION_DIR}/$SERVER_PRIVATE_KEY_PEM
  rm -f ${DESTINATION_DIR}/$SERVER_RSA_PRIVATE_KEY_PEM
  rm -f ${DESTINATION_DIR}/$SERVER_CA_RSA_PRIVATE_KEY_PEM
}

remove_extplugtest_keys() {
  echo "remove keys from cf-extplugtest-server"
  DESTINATION_DIR=../../demo-apps/cf-extplugtest-server/service
  rm -f ${DESTINATION_DIR}/$CA_TRUST_STORE_PEM
  rm -f ${DESTINATION_DIR}/$CLIENT_KEY_STORE_PEM
  rm -f ${DESTINATION_DIR}/$SERVER_KEY_STORE_PEM
}

create_keys() {
   echo "creating root key and certificate..."
   keytool -genkeypair -alias root -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-root' \
        -ext BC=ca:true -validity $VALIDITY -keypass $TRUST_STORE_PWD -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -storetype $DEFAULT_STORE_TYPE
   keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -certreq -alias root | \
      keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias root -gencert -validity $VALIDITY -ext BC=ca:true -rfc > $ROOT_CER
   keytool -alias root -noprompt -importcert -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -file $ROOT_CER -storetype $DEFAULT_STORE_TYPE

   echo "creating CA key and certificate..."
   keytool -genkeypair -alias ca -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-ca' \
        -ext BC=1 -validity $VALIDITY -keypass $TRUST_STORE_PWD -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD
   keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -certreq -alias ca | \
      keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias root -gencert -validity $VALIDITY -ext BC=1 -ext KU=keyCertSign,cRLSign -sigalg SHA256withECDSA -rfc > $CA_CER
   keytool -alias ca -importcert -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -file $CA_CER

   echo "creating CA key and alternative certificate with same DN ..."
   keytool -genkeypair -alias caalt -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-ca' \
        -ext BC=1 -validity $VALIDITY -keypass $TRUST_STORE_PWD -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD
   keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -certreq -alias caalt | \
      keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias root -gencert -validity $VALIDITY -ext BC=1 -ext KU=keyCertSign,cRLSign -sigalg SHA256withECDSA -rfc > $CA_CER
   keytool -alias caalt -importcert -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -file $CA_CER

   echo "creating server key and certificate..."
   keytool -genkeypair -alias server -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server' \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD -storetype $DEFAULT_STORE_TYPE
   keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias server | \
      keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias ca -gencert -ext KU=dig -ext \
      'san=dns:my.test.server,dns:californium.eclipseprojects.io,ip:35.185.40.182,dns:localhost,ip:127.0.0.1,ip:::1' \
      -validity $VALIDITY -sigalg SHA256withECDSA -rfc > $SERVER_CER
   keytool -alias server -noprompt -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file $SERVER_CER -storetype $DEFAULT_STORE_TYPE

   echo "creating server rsa-key and certificate..."
   keytool -genkeypair -alias serverrsa -keyalg RSA -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server-rsa' \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD -storetype $DEFAULT_STORE_TYPE
   keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias serverrsa | \
      keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias ca -gencert -ext KU=dig \
      -ext 'san=dns:localhost,ip:127.0.0.1,ip:::1,dns:californium.eclipseprojects.io,ip:35.185.40.182' \
      -validity $VALIDITY -sigalg SHA256withECDSA -rfc > $SERVER_RSA_CER
   keytool -alias serverrsa -noprompt -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file $SERVER_RSA_CER -storetype $DEFAULT_STORE_TYPE

   echo "creating CA2 key and certificate..."
   keytool -genkeypair -alias ca2 -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-ca2' \
        -ext BC=0 -validity $VALIDITY -keypass $TRUST_STORE_PWD -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD
   keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -certreq -alias ca2 | \
      keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias ca -gencert -validity $VALIDITY -ext BC=0 -ext KU=keyCertSign,cRLSign -sigalg SHA256withECDSA -rfc > $CA2_CER
   keytool -alias ca2 -noprompt -importcert -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -file $CA2_CER

   echo "creating serverlarge key and certificate..."
   keytool -genkeypair -alias serverlarge -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-serverlarge' \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
   keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias serverlarge | \
      keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias ca2 -gencert -ext KU=dig -ext \
      'san=ip:127.0.0.1,ip:::1' -validity $VALIDITY -sigalg SHA256withECDSA -rfc > $SERVER_LARGE_CER
   keytool -alias serverlarge -noprompt -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file $SERVER_LARGE_CER

   echo "creating CA RSA key and certificate..."
   keytool -genkeypair -alias carsa -keyalg RSA -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-ca-rsa' \
        -ext BC=0 -validity $VALIDITY -keypass $TRUST_STORE_PWD -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD
   keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -certreq -alias carsa | \
      keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias root -gencert -validity $VALIDITY -ext BC=0 -ext KU=keyCertSign,cRLSign -sigalg SHA256withECDSA -rfc > $CA_RSA_CER
   keytool -alias carsa -noprompt -importcert -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -file $CA_RSA_CER

   echo "creating server key with ca-rsa and certificate..."
   keytool -genkeypair -alias servercarsa -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server-ca-rsa' \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
   keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias servercarsa | \
      keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias carsa -gencert -ext KU=dig -ext \
      'san=dns:my.test.server2,dns:localhost,ip:127.0.0.1,ip:::1' -validity $VALIDITY -sigalg SHA256withRSA -rfc > $SERVER_CA_RSA_CER
   keytool -alias servercarsa -noprompt -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file $SERVER_CA_RSA_CER

   echo "creating client key and certificate..."
   keytool -genkeypair -alias client -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client' \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
   keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias client | \
        keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias ca -gencert -ext KU=dig \
        -validity $VALIDITY -sigalg SHA256withECDSA -rfc > $CLIENT_CER
   keytool -alias client -noprompt -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file $CLIENT_CER

   echo "creating expired client key and certificate..."
   keytool -genkeypair -alias clientexpired -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client-expired' \
        -validity 1 -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
   keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias clientexpired | \
        keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias ca -gencert -ext KU=dig \
        -validity 1 -sigalg SHA256withECDSA -rfc > $CLIENT_EXPIRED_CER
   keytool -alias clientexpired -noprompt -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file $CLIENT_EXPIRED_CER

   echo "creating client rsa-key and certificate..."
   keytool -genkeypair -alias clientrsa -keyalg RSA -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client-rsa' \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
   keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias clientrsa | \
        keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias ca -gencert -ext KU=dig \
       -validity $VALIDITY -sigalg SHA256withECDSA -rfc > $CLIENT_RSA_CER
   keytool -alias clientrsa -noprompt -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file $CLIENT_RSA_CER

   echo "creating self-signed key and certificate..."
   keytool -genkeypair -alias self -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-self' \
        -ext BC=ca:true -ext KU=keyCertSign -ext KU=dig -validity $VALIDITY -sigalg SHA256withECDSA -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD

   echo "creating certificate with no digitalSignature keyusage..."
   keytool -genkeypair -alias nosigning -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-nosigning' \
        -ext BC=ca:true -ext KU=keyEn -validity $VALIDITY -sigalg SHA256withECDSA -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD

   echo "creating client key and certificate with extended keyusage..."
   keytool -genkeypair -alias clientext -keyalg EC -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-clientext' \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $KEY_STORE -storepass $KEY_STORE_PWD
   keytool -keystore $KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias clientext | \
        keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias ca -gencert -ext KU=dig -ext EKU=clientAuth \
        -validity $VALIDITY -sigalg SHA256withECDSA -rfc > $CLIENT_EXT_CER
   # the keytool supports two modes of certificates import
   # - import a certificate chain (as it is)
   # - import a certificate (and amend the chain from the CA certificates in the store)
   # gencert creates a chain excluding the top-level self-signed root-certificate from that chain
   # importing a single signed certificate amend also this top-level self-signed roo-tcertificate to that chain
   # to test the behaviour for certificate chains including the top-level self-signed root-certificate, amend it to the chain generated by gencert 
   cat $ROOT_CER >> $CLIENT_EXT_CER  
   keytool -alias clientext -noprompt -importcert -keystore $KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts -file $CLIENT_EXT_CER

   # requires java 15!
   # sudo update-java-alternatives -s java-1.15.0-openjdk-amd64
   echo "creating client eddsa key and certificate..."
   keytool -genkeypair -alias clienteddsa -keyalg Ed25519 -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client-eddsa' \
        -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $EDDSA_KEY_STORE -storepass $KEY_STORE_PWD -storetype $DEFAULT_STORE_TYPE

   if [ $? -eq 0 ] ; then 
   
      keytool -keystore $EDDSA_KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias clienteddsa | \
           keytool -keystore $TRUST_STORE -storepass $TRUST_STORE_PWD -alias ca -gencert -ext KU=dig \
           -validity $VALIDITY -sigalg SHA256withECDSA -rfc > $CLIENT_EDDSA_CER
      keytool -alias clienteddsa -noprompt -importcert -keystore $EDDSA_KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts \
           -file $CLIENT_EDDSA_CER -storetype $DEFAULT_STORE_TYPE

      echo "import other key and certificate into eddsa trust ..."
      keytool -importkeystore -destkeystore $EDDSA_TRUST_STORE -deststorepass $TRUST_STORE_PWD \
           -srckeystore $TRUST_STORE -srcstorepass $TRUST_STORE_PWD -storetype $DEFAULT_STORE_TYPE

      echo "creating CA EdDsa key and certificate..."
      keytool -genkeypair -alias caeddsa -keyalg Ed25519 -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-ca-eddsa' \
           -ext BC=1 -validity $VALIDITY -keypass $TRUST_STORE_PWD -keystore $EDDSA_TRUST_STORE -storepass $TRUST_STORE_PWD
      keytool -keystore $EDDSA_TRUST_STORE -storepass $TRUST_STORE_PWD -certreq -alias caeddsa | \
           keytool -keystore $EDDSA_TRUST_STORE -storepass $TRUST_STORE_PWD -alias root -gencert -validity $VALIDITY \
           -ext BC=1 -ext KU=keyCertSign,cRLSign -sigalg SHA256withECDSA -rfc > $CA_EDDSA_CER
      keytool -alias caeddsa -importcert -keystore $EDDSA_TRUST_STORE -storepass $TRUST_STORE_PWD -file $CA_EDDSA_CER

      echo "creating server eddsa key and certificate..."
      keytool -genkeypair -alias servereddsa -keyalg Ed25519 -dname 'C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server-eddsa' \
           -validity $VALIDITY -keypass $KEY_STORE_PWD -keystore $EDDSA_KEY_STORE -storepass $KEY_STORE_PWD -storetype $DEFAULT_STORE_TYPE
      keytool -keystore $EDDSA_KEY_STORE -storepass $KEY_STORE_PWD -certreq -alias servereddsa | \
           keytool -keystore $EDDSA_TRUST_STORE -storepass $TRUST_STORE_PWD -alias caeddsa -gencert -ext KU=dig \
           -ext 'san=dns:localhost,ip:127.0.0.1,ip:::1,dns:californium.eclipseprojects.io,ip:35.185.40.182' \
           -validity $VALIDITY -sigalg Ed25519 -rfc > $SERVER_EDDSA_CER
      keytool -alias servereddsa -noprompt -importcert -keystore $EDDSA_KEY_STORE -storepass $KEY_STORE_PWD -trustcacerts \
           -file $SERVER_EDDSA_CER -storetype $DEFAULT_STORE_TYPE

      echo "import other key and certificate into eddsa store ..."
      keytool -importkeystore -destkeystore $EDDSA_KEY_STORE -deststorepass $KEY_STORE_PWD \
           -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD -storetype $DEFAULT_STORE_TYPE

   else
      echo "keytool doesn't support EdDSA! Use java 15 or newer."
      rm -f $EDDSA_KEY_STORE 
   fi
}

export_p12() {
   if [ -z "$LEGACY" ]  ; then
      echo "exporting keys into PKCS#12 format"
   else
      echo "exporting keys into PKCS#12 format to support android (legacy encryption)"
   fi	
   keytool $LEGACY -v -importkeystore -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD -alias client \
      -destkeystore $CLIENT_KEY_STORE_P12 -deststorepass $KEY_STORE_PWD -deststoretype PKCS12
   keytool $LEGACY -v -importkeystore -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD -alias clientrsa \
      -destkeystore $CLIENT_RSA_KEY_STORE_P12 -deststorepass $KEY_STORE_PWD -deststoretype PKCS12
   keytool $LEGACY -v -importkeystore -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD -alias server \
      -destkeystore $SERVER_KEY_STORE_P12 -deststorepass $KEY_STORE_PWD -deststoretype PKCS12
   keytool $LEGACY -v -importkeystore -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD -alias serverlarge \
      -destkeystore $SERVER_LARGE_KEY_STORE_P12 -deststorepass $KEY_STORE_PWD -deststoretype PKCS12
   keytool $LEGACY -v -importkeystore -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD -alias serverrsa \
      -destkeystore $SERVER_RSA_KEY_STORE_P12 -deststorepass $KEY_STORE_PWD -deststoretype PKCS12
   keytool $LEGACY -v -importkeystore -srckeystore $KEY_STORE -srcstorepass $KEY_STORE_PWD -alias servercarsa \
      -destkeystore $SERVER_CA_RSA_KEY_STORE_P12 -deststorepass $KEY_STORE_PWD -deststoretype PKCS12
   keytool $LEGACY -v -importkeystore -srckeystore $TRUST_STORE -srcstorepass $TRUST_STORE_PWD -alias root \
      -destkeystore $ROOT_TRUST_STORE_P12 -deststorepass $TRUST_STORE_PWD -deststoretype PKCS12
   keytool $LEGACY -v -importkeystore -srckeystore $TRUST_STORE -srcstorepass $TRUST_STORE_PWD -alias ca \
      -destkeystore $CA_TRUST_STORE_P12 -deststorepass $TRUST_STORE_PWD -deststoretype PKCS12
   keytool $LEGACY -v -importkeystore -srckeystore $TRUST_STORE -srcstorepass $TRUST_STORE_PWD -alias carsa \
      -destkeystore $CA_RSA_TRUST_STORE_P12 -deststorepass $TRUST_STORE_PWD -deststoretype PKCS12
   keytool $LEGACY -v -importkeystore -srckeystore $TRUST_STORE -srcstorepass $TRUST_STORE_PWD \
      -destkeystore $TRUST_STORE_P12 -deststorepass $TRUST_STORE_PWD -deststoretype PKCS12 

   if [ -s $EDDSA_KEY_STORE ] ; then 
      keytool $LEGACY -v -importkeystore -srckeystore $EDDSA_KEY_STORE -srcstorepass $KEY_STORE_PWD -alias clienteddsa \
         -destkeystore $CLIENT_EDDSA_KEY_STORE_P12 -deststorepass $KEY_STORE_PWD -deststoretype PKCS12
      keytool $LEGACY -v -importkeystore -srckeystore $EDDSA_KEY_STORE -srcstorepass $KEY_STORE_PWD -alias servereddsa \
         -destkeystore $SERVER_EDDSA_KEY_STORE_P12 -deststorepass $KEY_STORE_PWD -deststoretype PKCS12 
   fi
   if [ -s $EDDSA_TRUST_STORE ] ; then 
      keytool $LEGACY -v -importkeystore -srckeystore $EDDSA_TRUST_STORE -srcstorepass $TRUST_STORE_PWD \
         -destkeystore $EDDSA_TRUST_STORE_P12 -deststorepass $TRUST_STORE_PWD -deststoretype PKCS12 
      keytool $LEGACY -v -importkeystore -srckeystore $EDDSA_TRUST_STORE -srcstorepass $TRUST_STORE_PWD -alias caeddsa \
         -destkeystore $CA_EDDSA_TRUST_STORE_P12 -deststorepass $TRUST_STORE_PWD -deststoretype PKCS12
   fi

}

export_pem() {
   openssl version

   if [ $? -eq 0 ] ; then
      echo "exporting keys into PEM format"
      openssl pkcs12 -in $SERVER_KEY_STORE_P12 -passin pass:$KEY_STORE_PWD -nodes -out $SERVER_KEY_STORE_PEM
      openssl pkcs12 -in $SERVER_LARGE_KEY_STORE_P12 -passin pass:$KEY_STORE_PWD -nodes -out $SERVER_LARGE_KEY_STORE_PEM
      openssl pkcs12 -in $SERVER_RSA_KEY_STORE_P12 -passin pass:$KEY_STORE_PWD -nodes -out $SERVER_RSA_KEY_STORE_PEM
      openssl pkcs12 -in $SERVER_CA_RSA_KEY_STORE_P12 -passin pass:$KEY_STORE_PWD -nodes -out $SERVER_CA_RSA_KEY_STORE_PEM
      if [ -s $SERVER_EDDSA_KEY_STORE_P12 ] ; then 
         openssl pkcs12 -in $SERVER_EDDSA_KEY_STORE_P12 -passin pass:$KEY_STORE_PWD -nodes -out $SERVER_EDDSA_KEY_STORE_PEM
      fi
      openssl pkcs12 -in $CLIENT_KEY_STORE_P12 -passin pass:$KEY_STORE_PWD -nodes -out $CLIENT_KEY_STORE_PEM
      openssl pkcs12 -in $CLIENT_RSA_KEY_STORE_P12 -passin pass:$KEY_STORE_PWD -nodes -out $CLIENT_RSA_KEY_STORE_PEM
      if [ -s $SERVER_EDDSA_KEY_STORE_P12 ] ; then 
         openssl pkcs12 -in $CLIENT_EDDSA_KEY_STORE_P12 -passin pass:$KEY_STORE_PWD -nodes -out $CLIENT_EDDSA_KEY_STORE_PEM
      fi
      openssl pkcs12 -in $ROOT_TRUST_STORE_P12 -passin pass:$TRUST_STORE_PWD -nokeys -out $ROOT_TRUST_STORE_PEM
      openssl pkcs12 -in $CA_TRUST_STORE_P12 -passin pass:$TRUST_STORE_PWD -nokeys -out $CA_TRUST_STORE_PEM
      openssl pkcs12 -in $CA_RSA_TRUST_STORE_P12 -passin pass:$TRUST_STORE_PWD -nokeys -out $CA_RSA_TRUST_STORE_PEM
      if [ -s $CA_EDDSA_TRUST_STORE_P12 ] ; then 
         openssl pkcs12 -in $CA_EDDSA_TRUST_STORE_P12 -passin pass:$TRUST_STORE_PWD -nodes -out $CA_EDDSA_TRUST_STORE_PEM
      fi
      openssl pkcs12 -in $TRUST_STORE_P12 -passin pass:$TRUST_STORE_PWD -nokeys -out $TRUST_STORE_PEM
      openssl ecparam -genkey -name prime256v1 -noout -out $EC_PRIVATE_KEY_PEM
      openssl ec -in $EC_PRIVATE_KEY_PEM -pubout -out $EC_PUBLIC_KEY_PEM
      openssl genpkey -algorithm Ed25519 -out $ED25519_PRIVATE_KEY_PEM
      openssl pkey -in $ED25519_PRIVATE_KEY_PEM -pubout -out $ED25519_PUBLIC_KEY_PEM
      openssl genpkey -algorithm Ed448 -out $ED448_PRIVATE_KEY_PEM
      openssl pkey -in $ED448_PRIVATE_KEY_PEM -pubout -out $ED448_PUBLIC_KEY_PEM
     
      # GnuTLS interoperability tests 
      docker pull ubuntu:trusty
      if [ $? -eq 0 ] ; then   
         echo "openssl: (docker ubuntu.trusty)"
         docker run ubuntu:trusty /usr/bin/openssl version
         DESTINATION_DIR=../../../../californium-tests/californium-interoperability-tests
         echo "exporting private keys into GnuTLS PEM format"
         openssl pkey -in $CLIENT_KEY_STORE_PEM | docker run -i ubuntu:trusty /usr/bin/openssl pkey > $CLIENT_PRIVATE_KEY_PEM
         openssl pkey -in $CLIENT_RSA_KEY_STORE_PEM | docker run -i ubuntu:trusty /usr/bin/openssl pkey > $CLIENT_RSA_PRIVATE_KEY_PEM
         openssl pkey -in $SERVER_KEY_STORE_PEM | docker run -i ubuntu:trusty /usr/bin/openssl pkey > $SERVER_PRIVATE_KEY_PEM
         openssl pkey -in $SERVER_RSA_KEY_STORE_PEM | docker run -i ubuntu:trusty /usr/bin/openssl pkey > $SERVER_RSA_PRIVATE_KEY_PEM
         openssl pkey -in $SERVER_CA_RSA_KEY_STORE_PEM | docker run -i ubuntu:trusty /usr/bin/openssl pkey > $SERVER_CA_RSA_PRIVATE_KEY_PEM
      else 
         echo "Missing docker, no private keys for GnuTLS interoperability tests are exported."
      fi
   else 
      echo "missing openssl, no pem credentials are exported."
   fi
} 

copy_pem() {
  echo "copy to californium-interoperability-tests"
  DESTINATION_DIR=../../californium-tests/californium-interoperability-tests
  cp $TRUST_STORE_PEM $DESTINATION_DIR
  cp $ROOT_TRUST_STORE_PEM $DESTINATION_DIR
  cp $CA_TRUST_STORE_PEM $DESTINATION_DIR
  cp $CA_RSA_TRUST_STORE_PEM $DESTINATION_DIR
  if [ -s $CA_EDDSA_TRUST_STORE_PEM ] ; then 
  	cp $CA_EDDSA_TRUST_STORE_PEM $DESTINATION_DIR
  fi
  cp $CLIENT_KEY_STORE_PEM $DESTINATION_DIR
  cp $CLIENT_RSA_KEY_STORE_PEM $DESTINATION_DIR
  if [ -s $CLIENT_EDDSA_KEY_STORE_PEM ] ; then 
  	cp $CLIENT_EDDSA_KEY_STORE_PEM $DESTINATION_DIR
  fi
  cp $SERVER_KEY_STORE_PEM $DESTINATION_DIR
  cp $SERVER_LARGE_KEY_STORE_PEM $DESTINATION_DIR
  cp $SERVER_RSA_KEY_STORE_PEM $DESTINATION_DIR
  cp $SERVER_CA_RSA_KEY_STORE_PEM $DESTINATION_DIR
  if [ -s $SERVER_EDDSA_KEY_STORE_PEM ] ; then 
  	cp $SERVER_EDDSA_KEY_STORE_PEM $DESTINATION_DIR
  fi
  cp $EC_PRIVATE_KEY_PEM $DESTINATION_DIR
  cp $CLIENT_PRIVATE_KEY_PEM $DESTINATION_DIR
  cp $CLIENT_RSA_PRIVATE_KEY_PEM $DESTINATION_DIR
  cp $SERVER_PRIVATE_KEY_PEM $DESTINATION_DIR
  cp $SERVER_RSA_PRIVATE_KEY_PEM $DESTINATION_DIR

  echo "copy to cf-extplugtest-server"
  DESTINATION_DIR=../../demo-apps/cf-extplugtest-server/service
  cp $CA_TRUST_STORE_PEM $DESTINATION_DIR
  cp $CLIENT_KEY_STORE_PEM $DESTINATION_DIR
  cp $SERVER_KEY_STORE_PEM $DESTINATION_DIR
}

jobs () {
  echo "$1"
  case $1 in
     "remove")
        remove_keys
	remove_interop_keys
	remove_extplugtest_keys
	;;
     "create")
        create_keys
	;;
     "export")
        export_p12
        export_pem
	;;
     "copy")
        copy_pem
	;;
  esac
}

if [ -z "$1" ]  ; then
     echo "default: remove create export copy"
     JOBS="remove create export copy"
else 
     JOBS=$@	
fi

for JOB in ${JOBS}; do
   jobs ${JOB}
done
