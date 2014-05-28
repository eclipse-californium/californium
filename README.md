Scandium (Sc) Security for Californium
======================================

Scandium (Sc) is a DTLS 1.2 implementation for the Californium (Cf) CoAP framework.
It uses the [element-connector](https://github.com/eclipse/californium.element-connector)
interface, which is a socket-like API to send and receive raw data and allows
the modularization of Californium (Cf). Hence, Scandium (Sc) can also be used
standalone, i.e. without Californium's CoAP implementation on top.

Maven
-----

Usually Scandium (Sc) is included as Maven dependency in the main project:

```xml
  <dependencies>
    ...
    <dependency>
            <groupId>org.eclipse.californium</groupId>
            <artifactId>scandium</artifactId>
            <version>1.0.0-SNAPSHOT</version>
    </dependency>
    ...
  </dependencies>
  
  <repositories>
    ...
    <repository>
      <id>repo.eclipse.org</id>
      <name>Californium Repository - Releases</name>
      <url>https://repo.eclipse.org/content/repositories/californium-releases/</url>
    </repository>
    <repository>
      <id>repo.eclipse.org</id>
      <name>Californium Repository - Snapshots</name>
      <url>https://repo.eclipse.org/content/repositories/californium-snapshots/</url>
    </repository>
    ...
  </repositories>
```

Alternatively, use `mvn clean install` in the root directory to build
and install the artifact locally.

Eclipse
-------

The project also includes the project files for Eclipse. Make sure to have the
following before importing the Scandium (Sc) project:

* [Eclipse EGit](http://www.eclipse.org/egit/)
* [m2e - Maven Integration for Eclipse](http://www.eclipse.org/m2e/)
* UTF-8 workspace text file encoding (Preferences &raquo; General &raquo; Workspace)

Then choose *[Import... &raquo; Git &raquo; Projects from Git &raquo; Local]*
to import Californium into Eclipse.

Included Certificates
---------------------

The sub-directory `certs` contains the Java key stores to run Scandium (Sc).

### Trust Store

*	Contains the self-signed root CA: *Cf Root CA*
*	Password: `rootPass`

### Key Store

*	Contains the certificate chain for DTLS endpoints: *Cf Client CA* and *Cf Server CA* 
*	Password: `endPass`

Creating Certificates
---------------------

Having OpenSSL installed, certificates and key stores can be created with the
following steps:

	# Create private key and self-signed root CA
	openssl ecparam -name prime256v1 -genkey -out root.key
	openssl req -new -key root.key -x509 -sha256 -days 365 -out root.crt
	
	# Create private key, signing request, and sign with root CA
	openssl ecparam -name prime256v1 -genkey -out inter.key
	openssl req -new -key inter.key -sha256 -out inter.csr
	openssl x509 -sha256 -req -in inter.csr -CA root.crt -CAkey root.key -out inter.crt -days 365 -CAcreateserial
	
	# Import root CA into Java's trusted CAs
	keytool -importcert -alias californium -file root.crt -keystore "$JAVA_HOME/jre/lib/security/cacerts"
	
	# Import root CA into portable trust store
	keytool -importcert -alias root -file root.crt -keystore trustStore.jks
	
	# Create client CA and import certificate chain into key store
	keytool -genkeypair -alias client -keyalg EC -keystore keyStore.jks -sigalg SHA256withECDSA -validity 365
	keytool -certreq -alias client -keystore keyStore.jks -file client.csr
	openssl x509 -req -in client.csr -CA inter.crt -CAkey inter.key -out client.crt -sha256 -days 365 -CAcreateserial
	keytool -importcert -alias inter -file inter.crt -keystore keyStore.jks -trustcacerts
	keytool -importcert -alias client -file client.crt -keystore keyStore.jks -trustcacerts
	
	# Create server CA and import certificate chain into key store
	keytool -genkeypair -alias server -keyalg EC -keystore keyStore.jks -sigalg SHA256withECDSA -validity 365
	keytool -certreq -alias server -keystore keyStore.jks -file server.csr
	openssl x509 -req -in server.csr -CA inter.crt -CAkey inter.key -out server.crt -sha256 -days 365 -CAcreateserial
	keytool -importcert -alias server -file server.crt -keystore keyStore.jks -trustcacerts
	
	# List certificate chain in key store
	keytool -list -v -keystore keyStore.jks