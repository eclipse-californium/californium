![Scandium logo](sc_64.png)

# Scandium (Sc) - Security for Californium

_Scandium (Sc)_  is a pure Java implementation of  _Datagram Transport Layer Security 1.2_ , also known as [RFC 6347](https://tools.ietf.org/html/rfc6347), for the [Californium (Cf)](https://www.eclipse.org/californium/) CoAP framework. DTLS is based on TLS [RFC 5246](https://tools.ietf.org/html/rfc5246) and adapts it for the usage with UDP. 

_Scandium (Sc)_  implements the [element-connector](https://github.com/eclipse/californium/tree/master/element-connector) interface which provides a socket-like API for sending and receiving raw data chunks (byte arrays). Hence, you can also use  _Scandium (Sc)_  as a standalone library providing a secure UDP based transport layer to any type of application
sitting on top of it.

# Usage

If you search the Web, you will find many references and snippets how to setup DTLS for Californium.
Unfortunately, the most are just deprecated. Since 3.0.0-RC1 it comes now even with the new `Configuration` and applies therefore more changes.

One good point to start with is reading the javadoc of [DtlsConnectorConfig](src/main/java/org/eclipse/californium/scandium/config/DtlsConnectorConfig.java).

The general idea is, that you provide the credentials, and the auto-configuration does the rest. If you need a more specific setup, you may consider to read [DtlsConfig](src/main/java/org/eclipse/californium/scandium/config/DtlsConfig.java) in order see, which parameters may be configured.

## PSK

PSK credentials are provided using a implementation of the [AdvancedPskStore](src/main/java/org/eclipse/californium/scandium/dtls/pskstore/AdvancedPskStore.java) interface.

For demonstration, two implementations for server- and client-usage are available ([AdvancedMultiPskStore](src/main/java/org/eclipse/californium/scandium/dtls/pskstore/AdvancedMultiPskStore.java) and [AdvancedSinglePskStore](src/main/java/org/eclipse/californium/scandium/dtls/pskstore/AdvancedSinglePskStore.java)).

Using the interface enables also implementations, which are providing the credentials dynamically. If that is done in a way with larger latency (e.g. remote call), also a asynchronous implementation is possible.

## RPK/X509

Certificate based credentials are provided using a implementation of the [CertificateProvider](src/main/java/org/eclipse/californium/scandium/dtls/x509/CertificateProvider.java) interface. And to verify certificates of the other peers, provide a implementation of the [NewAdvancedCertificateVerifier](src/main/java/org/eclipse/californium/scandium/dtls/x509/NewAdvancedCertificateVerifier.java).

For demonstration, two implementations of the `CertificateProvider` are available, the [SingleCertificateProvider](src/main/java/org/eclipse/californium/scandium/dtls/x509/SingleCertificateProvider.java) (for simple setups or setups with earlier versions of Californium), and the [KeyManagerCertificateProvider](src/main/java/org/eclipse/californium/scandium/dtls/x509/KeyManagerCertificateProvider.java) (for setups with multiple certificates in order to support different certificate types and/or other subjects/servernames).

Also for demonstration, one implementation of the `NewAdvancedCertificateVerifier` is available, the [StaticNewAdvancedCertificateVerifier](src/main/java/org/eclipse/californium/scandium/dtls/x509/StaticNewAdvancedCertificateVerifier.java).

## Additional Parameters

In order to limit the usage of some parameter, it is possible to provide them by the 
[DtlsConnectorConfig.Builder](src/main/java/org/eclipse/californium/scandium/config/DtlsConnectorConfig.java#L1437-L2279) using the definitions from [DtlsConfig](src/main/java/org/eclipse/californium/scandium/config/DtlsConfig.java).

```
...
DtlsConfig.register();
CoapConfig.register();
...
Configuration configuration ...
DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(configuration);
builder.set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY);
builder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
...
builder.build(); 
```

# Getting it

You can either use  _Scandium (Sc)_  binaries from Maven or you can build your own binaries from source code.

### Binaries

The most recent  _Scandium_  snapshot binaries are available from the Eclipse Foundation's Maven repository.
Simply add  _Scandium_  as as dependency to your Maven POM file as shown below. Don't forget to also add the definition for Eclipse's snapshot repository.

The  _Scandium_  release binaries are also available via Maven Central. Thus, you will
not need to define any additional Maven repos in your POM file or Maven settings.xml in order to get release versions.

See [Californium Project Plan](https://projects.eclipse.org/projects/iot.californium/governance) for scheduled releases.

```xml
  <dependencies>
    ...
    <dependency>
            <groupId>org.eclipse.californium</groupId>
            <artifactId>scandium</artifactId>
            <version>3.0.0</version>
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

If you want to build and install  _Scandium_  from source, simply run

```sh
mvn clean install
```

in the project's root directory.

This `scandium-core` folder contains the source code for the Scandium library.
The [demo-apps/sc-dtls-example-client](../demo-apps/sc-dtls-example-client) and [demo-apps/sc-dtls-example-server](../demo-apps/sc-dtls-example-server) folder contains some sample code illustrating how to configure and instantiate Scandium's [DTLSConnector](src/main/java/org/eclipse/californium/scandium/DTLSConnector.java) class to establish connections secured by DTLS.

Generally it's required to register the [DtlsConfig.register()](src/main/java/org/eclipse/californium/scandium/config/DtlsConfig.java) the DTLS configuration module or to provide it when using the `Configuration(ModuleDefinitionsProvider... providers)`.
For more advanced configuration options take a look at the definitions of [DtlsConfig](src/main/java/org/eclipse/californium/scandium/config/DtlsConfig.java) and [DtlsConnectorConfig](src/main/java/org/eclipse/californium/scandium/config/DtlsConnectorConfig.java) JavaDocs.

# Eclipse

The project also includes the project files for Eclipse. Make sure to have the
following before importing the Scandium (Sc) project:

* [Eclipse EGit](http://www.eclipse.org/egit/)
* [m2e - Maven Integration for Eclipse](http://www.eclipse.org/m2e/)
* UTF-8 workspace text file encoding (Preferences &raquo; General &raquo; Workspace)

Then choose *[Import... &raquo; Git &raquo; Projects from Git &raquo; Local]*
to import Californium into Eclipse.

# Demo Certificates

Scandium's test cases and examples refer to Java key stores containing private and public keys. These key stores are provided by the `demo-certs` module. Please refer to the documentation of that module for more information regarding how to create your own certificates.

Starting with 3.0.0-RC1 a client receiving a x509 server-certificate verifies the subject of it by default. This may be disabled using [DtlsConfig.DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT](src/main/java/org/eclipse/californium/scandium/config/DtlsConfig.java#L410).

Also Starting with 3.0.0-RC1, a server may use a `X509KeyManager` in order to provide multiple certificates to be selected by their algorithms and/or server name. For that, a Ed25519 and a RSA certificate has been added to the `demo-certs`.

# Supported RFCs

[Supported Cipher Suites](src/main/java/org/eclipse/californium/scandium/dtls/cipher/CipherSuite.java):

- TLS_ECDHE_ECDSA_WITH_AES_128_CCM
- TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_256_CCM
- TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256
- TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256
- TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA378
- TLS_PSK_WITH_AES_128_CCM
- TLS_PSK_WITH_AES_128_CCM_8
- TLS_PSK_WITH_AES_128_GCM_SHA256
- TLS_PSK_WITH_AES_256_CCM
- TLS_PSK_WITH_AES_256_CCM_8
- TLS_PSK_WITH_AES_256_GCM_SHA378
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

- *TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256*
- *TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA*
- *TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384*
- *TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256*
- *TLS_PSK_WITH_AES_128_CBC_SHA256*
- *TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
- *TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
- *TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA

Note: the *CBC* cipher suite are not longer recommended for new deployments!

Supported extensions:
- [RFC 4279 - Pre-Shared Key](https://tools.ietf.org/html/rfc4279) simple and light authentication.
- [RFC 4492 - Elliptic Curve Cryptography (ECC)](https://tools.ietf.org/html/rfc4492)
- [RFC 8422 - Elliptic Curve Cryptography (ECC) Update](https://tools.ietf.org/html/rfc8422)
- [RFC 5489 - ECDHE_PSK Cipher Suites](https://tools.ietf.org/html/rfc5489)
- [RFC 6066 - TLS Extensions](https://tools.ietf.org/html/rfc6066)
     - [RFC 6066 - Server Name Indication](https://tools.ietf.org/html/rfc6066#section-3)
     - [RFC 6066 - Maximum Fragment Length Negotiation](https://tools.ietf.org/html/rfc6066#section-4)
     - [RFC 7627 - Extended Master Secret Extension](https://tools.ietf.org/html/rfc7627)
     - [RFC 8449 - Record Size Limit Extension ](https://tools.ietf.org/html/rfc8449)
     - [Draft - Connection Identifiers for DTLS 1.2](https://datatracker.ietf.org/doc/draft-ietf-tls-dtls-connection-id)
- [RFC 7250 - Raw Public Keys](https://tools.ietf.org/html/rfc7250)
- [RFC 7748 - Elliptic Curves for Security](https://tools.ietf.org/html/rfc7748)

## Support for x25519 and ed25519

Support for X25519 is only available using java 11 (or newer) for execution.
Support for ED25519 is only available using java 15 (or newer) for execution,
or java 11 (or newer) and a third party library [ed25519-java](https://github.com/str4d/ed25519-java). Building  _Scandium_  using java 11 therefore includes that third party library to the classpath. Use

```sh
mvn clean install -Dno.net.i2p.crypto.eddsa=true
```

if this library should not be included.

## Support for Bouncy Castle

Starting with 3.0.0-RC1 an experimental support for using [Bouncy Castle](https://www.bouncycastle.org/) as alternative JCE has been implemented. Add the maven dependencies

```
<properties>
	<bc.version>1.69</bc.version>
</properties>
<dependencies>
	<dependency>
		<groupId>org.bouncycastle</groupId>
		<artifactId>bcpkix-jdk15on</artifactId>
		<version>${bc.version}</version>
		<scope>test</scope>
	</dependency>
	<dependency>
		<groupId>org.bouncycastle</groupId>
		<artifactId>bcprov-jdk15on</artifactId>
		<version>${bc.version}</version>
		<scope>test</scope>
	</dependency>
</dependencies>
```

And setup a environment variable `CALIFORNIUM_JCE_PROVIDER` using the value `BC` (see [JceProviderUtil](../element-connector/src/main/java/org/eclipse/californium/elements/util/JceProviderUtil.java) for more details) or use the java `System.property` `CALIFORNIUM_JCE_PROVIDER` to do so.

Supporting Bouncy Castle for the unit test uncovers a couple of differences, which required to adapt the implementation. It is assumed, that more will be found and more adaption will be required. If you find some, don't hesitate to report issues, perhaps research and analysis, and fixes. On the other hand, the project Californium will for now not be able to provide support for Bouncy Castle questions with or without relation to Californium. You may create issues, but it may be not possible for us to answer them.

On issue seems to be the `SecureRandom` generator, which shows in some environments strange CPU/time consumption.

# DTLS 1.2 / UDP - Considerations

Using UDP, especially in public networks, comes usually with the risk of being attacked with spoofed ip-messages. Something send messages with a manipulated source ip-address. In some cases this is done in order to make the destination peer sending messages to the "victim" at the manipulated source ip-address. And in some other cases this is done to exhaust the destination's resources itself. A good general overview is provided in [NetScout - What is Distributed Denial of Service (DDoS)?](https://www.netscout.com/what-is-ddos).

For Scandium, that mainly requires to:
- prevent to send amplified messages back to unverified sources
- prevent the own endpoint to allocate resources for unverified sources, at least not without limitation.


For both, (RFC6347 - 4.2.1.  Denial-of-Service Countermeasures)[https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.1] describes a technique using a "stateless cookie" in order to verify the source ip-address without amplification and without state.

Scandium is intended to use such a `HelloVerifyRequest`, if spoofing must be considered.

