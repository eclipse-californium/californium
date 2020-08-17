# Demo Certificates for Californium

Californium's security module *Scandium (Sc)* is an implementation of _Datagram Transport Layer Security 1.2_, also
known as [RFC 6347](http://tools.ietf.org/html/rfc6347). Scandium's test cases and many of Californium's examples that use security require some private and public keys for configuring DTLS.

This module provides some example Java key stores containing public/private key pairs and certificate chains to be used for configuring DTLS at the client and server side. 

### Included Keys and Certificates

The test cases for Scandium try to cover multiple setups regarding a reasonable PKI infrastructure. In order to do so, this module provides some sample keys and certificate chains contained in two Java key stores which can be found in the 
the `src/main/resources` folder.

We use a multi-level chain of trust as follows:

1. A pair of private/public EC keys along with a self signed certificate which together represent the root CA identity.
2. A pair of private/public EC keys along with a certificate signed with the root CA's key which together represent an intermediary CA identity.
3. A pair of private/public EC keys along with a certificate signed with the intermediary CA's key which together assert the identity of a *server*.
4. A pair of private/public EC keys along with a certificate signed with the intermediary CA's key which together assert the identity of a *client*.

For extended tests, 
5. A pair of private/public EC keys along with a certificate signed with the intermediary CA's key which together represent an second intermediary CA identity.
6. A pair of private/public EC keys along with a certificate signed with the second intermediary CA's key which together assert the identity of a *server* (large certificate).
7. A pair of private/public RSA keys along with a certificate signed with the root CA's key which together represent an intermediary RSA-CA identity.
8. A pair of private/public EC keys along with a certificate signed with the intermediary RSA-CA's key which together assert the identity of a *server*.
9. A pair of private/public EC keys along with a self signed certificate.
10. A pair of private/public EC keys along with a certificate using extended key usage for clientAuth, signed with the intermediary CA's key which together assert the identity of a *client*.
11. A pair of private/public EdDSA keys along with a certificate signed with the intermediary CA's key which together assert the identity of a *client* (requires java 15).

**Trust Store**

The `trustStore.jks` contains the self-signed certificate for the root CA (alias `root`) as well as the certificate chain for the intermediary CAs
(alias `ca` and `carsa`). And a second intermediary CA (alias `ca2`). These certificates are used as the *trust anchors* in Scandium's examples and test cases.

The password for accessing the trust store is `rootPass` by default.

For platforms without jks support, a p12 trust stores is also generated.
`trustStore.p12`, `caTrustStore.p12`, `caRsatrustStore.p12`.

**Key Store**

The `keyStore.jks` contains the keys and certificate chains for the *client* (alias `client`, `clientext`, and `clienteddsa` ) and
*server* (alias `server`, `serverlarge`, and `serverrsa`) identities.

The password for accessing the key store is `endPass` by default.

For platforms without jks support, a p12 trust stores is also generated.
`client.p12`, `clientEdDsa.p12`, `server.p12`, `serverLarge.p12`, and `serverRsa.p12`.

### Creating the Keys and Certificates

The key stores containing the demo keys and certificates can be recreated by means of the `create-keystores.sh` script. It uses the standard Java `keytool` to create keys and certificates.

You can also use the script to create your own certificates for use with Scandium. Simply alter the script at the places where you want to use other values as the default, e.g. your own distinguished names for the certificates and/or different key store names.

When running the script you will be prompted twice to trust the intermediary CA certificate so that it can be added to the key store. This is necessary because the `keytool` has no way to create a chain of trust from the *client* and *server* certificates to an already trusted root CA (because the demo root CA certificate is self-signed). Simply enter `yes` and press `enter` to trust the certificate and add it to the key store.

If you want to re-create the key stores you need to remove the two `jks` files manually before running the `create-keystores.sh` script. Otherwise, the `keytool` will exit when trying to add the newly created certificates under already existing aliases to the key stores.

The script supports a list of tasks as arguments. The supported tasks are:
-  remove remove all created files
-  create create keys an jks
-  export export p12 and pem

If no argument is provided "remove create export" is used.

Note: to create EdDSA certificates, it's required to use java 15. If previous java version are used, this client certificate is missing and the corresponding interoperability test is skipped.
