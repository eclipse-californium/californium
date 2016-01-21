# Scandium (Sc) - Security for Californium

_Scandium (Sc)_ is a pure Java implementation of _Datagram Transport Layer Security 1.2_, also
known as [RFC 6347](http://tools.ietf.org/html/rfc6347), for the [Californium (Cf)](https://iot.eclipse.org/Calirfornium)
CoAP framework.

_Scandium (Sc)_ implements the [element-connector](https://github.com/eclipse/californium.element-connector)
interface which provides a socket-like API for sending and receiving raw data chunks (byte arrays). Hence, you can
also use _Scandium (Sc)_ as a standalone library providing a secure UDP based transport layer to any type of application
sitting on top of it.

# Getting it

You can either use _Scandium (Sc)_ binaries from Maven or you can build your own binaries from source code.

### Binaries

The most recent _Scandium_ snapshot binaries are available from the Eclipse Foundation's Maven repository.
Simply add _Scandium_ as as dependency to your Maven POM file as shown below. Don't forget to also add
the definition for Eclipse's snapshot repository.

**Note**: We will provide _Scandium_ release binaries via Maven Central. Thus, you will
not need to define any additional Maven repos in your POM file or Maven settings.xml in order to get release versions.
See [Californium Project Plan](https://projects.eclipse.org/projects/technology.californium/governance) for scheduled releases.

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

### Building from Source

If you want to build and install _Scandium_ from source, simply run `mvn clean install` in the project's root directory.

The `scandium-core` folder contains the source code for the Scandium library.
The `scandium-examples` folder contains some sample code illustrating how to configure
and instantiate Scandium's `DTLSConnector` class to establish connections secured by DTLS. For more advanced
configuration options take a look at the `DtlsConnectorConfig` JavaDocs.

# Eclipse

The project also includes the project files for Eclipse. Make sure to have the
following before importing the Scandium (Sc) project:

* [Eclipse EGit](http://www.eclipse.org/egit/)
* [m2e - Maven Integration for Eclipse](http://www.eclipse.org/m2e/)
* UTF-8 workspace text file encoding (Preferences &raquo; General &raquo; Workspace)

Then choose *[Import... &raquo; Git &raquo; Projects from Git &raquo; Local]*
to import Californium into Eclipse.

# Certificates

### Included Certificates

The sub-directory `certs` contains Java key stores with example certificates for running Scandium's example code and test cases.

**Trust Store**

*	Contains the self-signed root CA: *Cf Root CA*
*	Password: `rootPass`

**Key Store**

*	Contains the certificate chain for DTLS endpoints: *Cf Client CA* and *Cf Server CA* 
*	Password: `endPass`

### Creating Certificates

You can create your own certificates for use with Scandium. Assuming that you have OpenSSL installed, certificates and key stores can be created following these steps:

	# Create private key and self-signed root CA
	openssl ecparam -name prime256v1 -genkey -out root.key
	openssl req -new -key root.key -x509 -sha256 -days 365 -out root.crt
	
	# Create private key, signing request for intermediary CA, and sign with root CA
	# the Basic Constraints specified in the inermediary_cert.extensions file are
	# necessary in order for clients to successfully validate certificate chains containing the
	# intermediary certificate
	openssl ecparam -name prime256v1 -genkey -out inter.key
	openssl req -new -key inter.key -sha256 -out inter.csr
	openssl x509 -sha256 -req -in inter.csr -CA root.crt -CAkey root.key -out inter.crt -days 365 -CAcreateserial -extfile intermediary_cert.extensions
	
	# Import root CA into Java's trusted CAs
	# This step is REQUIRED in order for the import of the client and server
	# certificates created in the next steps to successfully establish the
	# certificate chain (via the intermediary to the root CA) in the keystore 
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