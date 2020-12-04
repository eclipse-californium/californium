![Scandium logo](sc_64.png)

# Scandium (Sc) - Security for Californium

_Scandium (Sc)_  is a pure Java implementation of  _Datagram Transport Layer Security 1.2_ , also known as [RFC 6347](https://tools.ietf.org/html/rfc6347), for the [Californium (Cf)](https://www.eclipse.org/californium/) CoAP framework. DTLS is based on TLS [RFC 5246](https://tools.ietf.org/html/rfc5246) and adapts it for the usage with UDP. 

_Scandium (Sc)_  implements the [element-connector](https://github.com/eclipse/californium/tree/master/element-connector) interface which provides a socket-like API for sending and receiving raw data chunks (byte arrays). Hence, you can also use  _Scandium (Sc)_  as a standalone library providing a secure UDP based transport layer to any type of application
sitting on top of it.


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
            <version>2.6.0</version>
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
The [demo-apps/sc-dtls-example-client](https://github.com/eclipse/californium/tree/master/demo-apps/sc-dtls-example-client) and [demo-apps/sc-dtls-example-server](https://github.com/eclipse/californium/tree/master/demo-apps/sc-dtls-example-server) folder contains some sample code illustrating how to configure and instantiate Scandium's [DTLSConnector](https://github.com/eclipse/californium/blob/master/scandium-core/src/main/java/org/eclipse/californium/scandium/DTLSConnector.java) class to establish connections secured by DTLS. For more advanced configuration options take a look at the [DtlsConnectorConfig](https://github.com/eclipse/californium/blob/master/scandium-core/src/main/java/org/eclipse/californium/scandium/config/DtlsConnectorConfig.java) JavaDocs.

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
- *TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256*
- *TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA*
- *TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384*
- *TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256*
- *TLS_PSK_WITH_AES_128_CBC_SHA256*

Note: the *CBC* cipher suite are not longer recommended for new deployments!

Supported extensions:
- [RFC 4279 - Pre-Shared Key](https://tools.ietf.org/html/rfc4279) simple and light authentication.
- [RFC 4492 - Elliptic Curve Cryptography (ECC)](https://tools.ietf.org/html/rfc4492)
- [RFC 8422 - Elliptic Curve Cryptography (ECC) Update](https://tools.ietf.org/html/rfc8422)
- [RFC 5489 - ECDHE_PSK Cipher Suites](https://tools.ietf.org/html/rfc5489)
- [RFC 6066 - TLS Extensions](https://tools.ietf.org/html/rfc6066)
     - [RFC 6066 - Server Name Indication](https://tools.ietf.org/html/rfc6066#section-3)
     - [RFC 6066 - Maximum Fragment Length Negotiation](https://tools.ietf.org/html/rfc6066#section-4)
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
