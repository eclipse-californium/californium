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

Example:

```
...
DtlsConfig.register();
CoapConfig.register();
...
Configuration configuration = Configuration.getStandard();
DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(configuration);
builder.setAddress(new InetSocketAddress(5684));
...
```

## PSK

PSK credentials are provided using a implementation of the [AdvancedPskStore](src/main/java/org/eclipse/californium/scandium/dtls/pskstore/AdvancedPskStore.java) interface.

For demonstration, two implementations for server- and client-usage are available ([AdvancedMultiPskStore](src/main/java/org/eclipse/californium/scandium/dtls/pskstore/AdvancedMultiPskStore.java) and [AdvancedSinglePskStore](src/main/java/org/eclipse/californium/scandium/dtls/pskstore/AdvancedSinglePskStore.java)).

Using the interface enables also implementations, which are providing the credentials dynamically. If that is done in a way with larger latency (e.g. remote call), also a asynchronous implementation is possible. Such a design with larger latency will still cause delays in the handshakes and limit the possible handshakes in a period of time, but has only slightly effects on the other ongoing traffic.

Example:

```
...
DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(configuration);
builder.setAddress(new InetSocketAddress(5684));
AdvancedSinglePskStore pskStore = new AdvancedSinglePskStore("me", "secret".getBytes());
builder.setAdvancedPskStore(pskStore);

DTLSConnector connector = new DTLSConnector(builder.build());
```

## RPK/X509

Certificate based credentials are provided using a implementation of the [CertificateProvider](src/main/java/org/eclipse/californium/scandium/dtls/x509/CertificateProvider.java) interface. And to verify certificates of the other peers, provide a implementation of the [NewAdvancedCertificateVerifier](src/main/java/org/eclipse/californium/scandium/dtls/x509/NewAdvancedCertificateVerifier.java).

For demonstration, two implementations of the `CertificateProvider` are available, the [SingleCertificateProvider](src/main/java/org/eclipse/californium/scandium/dtls/x509/SingleCertificateProvider.java) (for simple setups or setups with earlier versions of Californium), and the [KeyManagerCertificateProvider](src/main/java/org/eclipse/californium/scandium/dtls/x509/KeyManagerCertificateProvider.java) (for setups with multiple certificates in order to support different certificate types and/or other subjects/servernames (SNI)).

Also for demonstration, one implementation of the `NewAdvancedCertificateVerifier` is available, the [StaticNewAdvancedCertificateVerifier](src/main/java/org/eclipse/californium/scandium/dtls/x509/StaticNewAdvancedCertificateVerifier.java).

Using the interfaces enables also implementations, which are providing the credentials dynamically. If that is done in a way with larger latency (e.g. remote call), also a asynchronous implementation is possible. Such a design with larger latency will still cause delays in the handshakes and limit the possible handshakes in a period of time, but has only slightly effects on the other ongoing traffic.

If the keys and/or certificate are stored in a file or key-store, one way to load them is using the [SslContextUtil](../element-connector#sslcontextutil).

Example:

```
// load credentials, see SslContextUtil
Credentials serverCredentials = SslContextUtil.loadCredentials(...);
Credentials serverTrusts = SslContextUtil.loadCredentials(...);
...
DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(configuration);
builder.setAddress(new InetSocketAddress(5684));

SingleCertificateProvider certificate = new SingleCertificateProvider(serverCredentials.getPrivateKey(), serverCredentials.getCertificateChain());
builder.setCertificateIdentityProvider(certificate);

NewAdvancedCertificateVerifier trust = StaticNewAdvancedCertificateVerifier.builder()
   .setTrustedCertificates(serverTrusts.getTrustedCertificates).build();
builder.setAdvancedCertificateVerifier(trust);

DTLSConnector connector = new DTLSConnector(builder.build());
```

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
            <version>3.10.0</version>
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

The `scandium-core` folder contains the source code for the Scandium library.
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

Starting with 3.0.0-RC1 a client receiving a x509 server-certificate verifies the subject of it by default. This may be disabled using [DtlsConfig.DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT](src/main/java/org/eclipse/californium/scandium/config/DtlsConfig.java#L416).

Also Starting with 3.0.0-RC1, a server may use a `X509KeyManager` in order to provide multiple certificates to be selected by their algorithms and/or server name. For that, a Ed25519 and a RSA certificate has been added to the `demo-certs`.

# Supported Features

## Supported Cipher Suites

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
- *TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA378*
- TLS_PSK_WITH_AES_128_CCM
- TLS_PSK_WITH_AES_128_CCM_8
- TLS_PSK_WITH_AES_128_GCM_SHA256
- TLS_PSK_WITH_AES_256_CCM
- TLS_PSK_WITH_AES_256_CCM_8
- *TLS_PSK_WITH_AES_256_GCM_SHA378*
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

- *TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256*
- *TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA*
- *TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384*
- *TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256*
- *TLS_PSK_WITH_AES_128_CBC_SHA256*
- *TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256*
- *TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384*
- *TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA*

ARIA cipher suites since 3.9.0, requires support by JCE, e.g. BouncyCastle 1.72:
- TLS_PSK_WITH_ARIA_128_GCM_SHA256
- TLS_PSK_WITH_ARIA_256_GCM_SHA384
- *TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256*
- *TLS_PSK_WITH_ARIA_128_CBC_SHA256*
- *TLS_PSK_WITH_ARIA_256_CBC_SHA384*
- TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384
- *TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256*
- *TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384*
- TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384

Note: the *CBC* cipher suites are not longer recommended for new deployments!

Note: *SHA378* in the cipher suite names are typos. It must be *SHA384*. The straight forward fix would break the API, therefore the fix is postponed to 4.0 (no schedule for now)!

## Supported Signature- and Hash-Algorithms

- *SHA256_WITH_ECDSA*
- *SHA256_WITH_RSA*
- *ED25519* (if supported by JCE)
- *ED448* (if supported by JCE)
- *SHA1_WITH_ECDSA* (if explicitly enabled)
- *SHA378_WITH_ECDSA* (if explicitly enabled)
- *SHA512_WITH_ECDSA* (if explicitly enabled)

## Supported Curves

- *secp256r1*
- *secp384r1*
- *secp521r1*
- *X25519* (if supported by JCE)
- *X448* (if supported by JCE)

(There are also some more, but their support depends on the JCE, see [SupportedGroup](src/main/java/org/eclipse/californium/scandium/dtls/cipher/XECDHECryptography.java#L351-L387)

## Supported RFCs

[RFC 6347 - Datagram Transport Layer Security Version 1.2](https://tools.ietf.org/html/rfc6347).

Supported extensions:
- [RFC 4279 - Pre-Shared Key](https://tools.ietf.org/html/rfc4279) simple and light authentication.
- [RFC 4492 - Elliptic Curve Cryptography (ECC)](https://tools.ietf.org/html/rfc4492)
- [RFC 5489 - ECDHE_PSK Cipher Suites](https://tools.ietf.org/html/rfc5489)
- [RFC 5705 -  Keying Material Exporters for Transport Layer Security (TLS)](https://tools.ietf.org/html/rfc5705)
- [RFC 5746 - Transport Layer Security (TLS) Renegotiation Indication Extension](https://tools.ietf.org/html/rfc5746) only minimal version, renegotiation is not supported at all!
- [RFC 6066 - TLS Extensions](https://tools.ietf.org/html/rfc6066)
     - [RFC 6066 - Server Name Indication](https://tools.ietf.org/html/rfc6066#section-3)
     - [RFC 6066 - Maximum Fragment Length Negotiation](https://tools.ietf.org/html/rfc6066#section-4)
- [RFC 6209 - ARIA Cipher Suites](https://tools.ietf.org/html/rfc6209) (since 3.9.0)
- [RFC 7250 - Raw Public Keys](https://tools.ietf.org/html/rfc7250)
- [RFC 7627 - Extended Master Secret Extension](https://tools.ietf.org/html/rfc7627)
- [RFC 7748 - Elliptic Curves for Security](https://tools.ietf.org/html/rfc7748)
- [RFC 8422 - Elliptic Curve Cryptography (ECC) Update](https://tools.ietf.org/html/rfc8422)
- [RFC 8449 - Record Size Limit Extension](https://tools.ietf.org/html/rfc8449)
- [RFC 9146 - Connection Identifiers for DTLS 1.2](https://www.rfc-editor.org/rfc/rfc9146.html)

## Support for x25519 and ed25519

Support for X25519 is only available using java 11 (or newer) for execution.
Support for ED25519 is only available using java 15 (or newer) for execution,
or java 11 (or newer) and a third party library [ed25519-java](https://github.com/str4d/ed25519-java). Building  _Scandium_  using java 11 therefore includes that third party library to the classpath. Use

```sh
mvn clean install -Dno.net.i2p.crypto.eddsa=true
```

if this library should not be included.

*Note:* using the oracle build 28 of openjdk 11 uncovers, that calling `EdDSAEngine.engineSetParameter(null)` fails with `ǸullPointerException` instead of `InvalidAlgorithmParameterException`. That causes to fail the verification of the signature at all. Using the aptopen build seems not to call `EdDSAEngine.engineSetParameter(null)` and therefore works. [ed25519-java](https://github.com/str4d/ed25519-java) seems to be not longer maintained. It's therefore recommended to update to newer jdks (e.g. 17) or to use Bouncy Castle (see next section, even if the Bouncy Castle support is experimental).

## Support for Bouncy Castle

Starting with 3.0.0-RC1 an experimental support for using [Bouncy Castle](https://www.bouncycastle.org/) as alternative JCE has been implemented. Add the maven dependencies

```
<properties>
	<bc.art>jdk18on</bc.art>
	<bc.version>1.77</bc.version>
	<slf4j.version>1.7.36</slf4j.version>
</properties>
<dependencies>
	<dependency>
		<groupId>org.bouncycastle</groupId>
		<artifactId>bcpkix-${bc.art}</artifactId>
		<version>${bc.version}</version>
	</dependency>
	<dependency>
		<groupId>org.bouncycastle</groupId>
		<artifactId>bcprov-${bc.art}</artifactId>
		<version>${bc.version}</version>
	</dependency>
	<dependency>
		<groupId>org.bouncycastle</groupId>
		<artifactId>bctls-${bc.art}</artifactId>
		<version>${bc.version}</version>
	</dependency>
	<dependency>
		<groupId>org.bouncycastle</groupId>
		<artifactId>bcutil-${bc.art}</artifactId>
		<version>${bc.version}</version>
	</dependency>
	<dependency>
		<groupId>org.slf4j</groupId>
		<artifactId>jul-to-slf4j</artifactId>
		<version>${slf4j.version}</version>
	</dependency>
</dependencies>
```

(With 3.3 the tests are using the updated version 1.70 instead of the 1.69, with 3.8 it is 1.72, with 3.9 it is 1.74, and with 3.10 it is 1.77).

And setup a environment variable `CALIFORNIUM_JCE_PROVIDER` using the value `BC` (see [JceProviderUtil](../element-connector/src/main/java/org/eclipse/californium/elements/util/JceProviderUtil.java) for more details) or use the java `System.property` `CALIFORNIUM_JCE_PROVIDER` to do so.

environment variable on unix:

```
export CALIFORNIUM_JCE_PROVIDER=BC
...
java ...
```
java `System.property`:

```
java -DCALIFORNIUM_JCE_PROVIDER=BC ...
```

Supporting Bouncy Castle for the unit test uncovers a couple of differences, which required to adapt the implementation. It is assumed, that more will be found and more adaption will be required. If you find some, don't hesitate to report issues, perhaps research and analysis, and fixes. On the other hand, the project Californium will for now not be able to provide support for Bouncy Castle questions with or without relation to Californium. You may create issues, but it may be not possible for us to answer them.

On issue seems to be the `SecureRandom` generator of BC. Dependent on the runtime environment, that is based on `SecureRandom.getInstanceStrong()`, which has blocking behaviour by default. If the platform your application runs on, has not enough entropy to start the `SecureRandom`, BC waits until that gets available. In common cases, that starts quite fast, but in some cases, that takes up to 60s (and more).

One option to overcome that on some linux variants is using `rng-tools`. That may help to provide more entropy.

A second option to overcome that is to setup `CALIFORNIUM_JCE_PROVIDER` using the value `BC_NON_BLOCKING_RANDOM` instead of `BC`. The `JceProviderUtil` then adapts `SecureRandom` to use a, maybe weaker, non-blocking `SecureRandom`. If that works, depends unfortunately on your platform, so especially for Android, that may not work. In that cases, please use `BC` as `CALIFORNIUM_JCE_PROVIDER` and configure "securerandom.strongAlgorithms" ahead with

```
Security.setProperty("securerandom.strongAlgorithms", "<your-android-algorithm>");
```

according your android variant. That may require some analysis by you.

# DTLS 1.2 / UDP - Considerations

## IP Spoofing - DDoS and Amplification
 
Using UDP, especially in public networks, comes usually with the risk of being attacked with spoofed ip-messages. Something send messages with a manipulated source ip-address. In some cases this is done in order to make the destination peer sending messages to the "victim" at the manipulated source ip-address. And in some other cases this is done to exhaust the destination's resources itself. A good general overview is provided in [NetScout - What is Distributed Denial of Service (DDoS)?](https://www.netscout.com/what-is-ddos).

For Scandium, that mainly requires to:
- prevent to send amplified messages back to unverified sources
- prevent the own endpoint to allocate resources for unverified sources, at least not without limitation.

For both, [RFC 6347 - 4.2.1.  Denial-of-Service Countermeasures](https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.1) describes a technique using a "stateless cookie" in order to verify the source ip-address without amplification and without state.

Scandium is intended to use such a `HelloVerifyRequest`, if spoofing must be considered.

[RFC 6347 - 4.2.1.  Denial-of-Service Countermeasures](https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.1) gives a server also a second option, when a client tries to resume a previous session.

    In addition, the server MAY choose not to do a cookie exchange when a session is resumed.

That option comes with [RFC 6347 - 4.2.8.  Establishing New Associations with Existing Parameters](https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.8)

    In cases where a server believes it has an existing association on a
    given host/port quartet and it receives an epoch=0 ClientHello, it
    SHOULD proceed with a new handshake but MUST NOT destroy the existing
    association until the client has demonstrated reachability either by
    completing a cookie exchange or by completing a complete handshake
    including delivering a verifiable Finished message. After a correct
    Finished message is received, the server MUST abandon the previous
    association to avoid confusion between two valid associations with
    overlapping epochs. The reachability requirement prevents
    off-path/blind attackers from destroying associations merely by
    sending forged ClientHellos.

Scandium hasn't implemented this second option. If spoofing must be considered, please always use a `HelloVerifyRequest`. Configure [DtlsConfig.DTLS_VERIFY_PEERS_ON_RESUMPTION_THRESHOLD](src/main/java/org/eclipse/californium/scandium/config/DtlsConfig.java#L621) therefore to `0`.

Additional configuration values, use with care:

- [DtlsConfig.DTLS_USE_HELLO_VERIFY_REQUEST_FOR_PSK](src/main/java/org/eclipse/californium/scandium/config/DtlsConfig.java#L637)
- [DtlsConfig.DTLS_USE_HELLO_VERIFY_REQUEST](src/main/java/org/eclipse/californium/scandium/config/DtlsConfig.java#L650)

## IP Spoofing - DoS - MAC Errors

Not only a large amplification of data may be a risk, also processing a DTLS record may introduce a risk, if IP spoofing must be considered.

Therefore RFC6347 says in [4.1.2.1 MAC](https://datatracker.ietf.org/doc/html/rfc6347#section-4.1.2.1):

    Note that one important difference between DTLS and TLS MAC handling
    is that in TLS, MAC errors must result in connection termination. In
    DTLS, the receiving implementation MAY simply discard the offending
    record and continue with the connection. This change is possible
    because DTLS records are not dependent on each other in the way that
    TLS records are.

and adds in [4.1.2.7 Handling Invalid Records](https://datatracker.ietf.org/doc/html/rfc6347#section-4.1.2.7):

    Unlike TLS, DTLS is resilient in the face of invalid records (e.g.,
    invalid formatting, length, MAC, etc.). In general, invalid records
    SHOULD be silently discarded, thus preserving the association;
    however, an error MAY be logged for diagnostic purposes.
    Implementations which choose to generate an alert instead, MUST
    generate fatal level alerts to avoid attacks where the attacker
    repeatedly probes the implementation to see how it responds to
    various types of error. Note that if DTLS is run over UDP, then any
    implementation which does this will be extremely susceptible to
    denial-of-service (DoS) attacks because UDP forgery is so easy.
    Thus, this practice is NOT RECOMMENDED for such transports.

In practice, that implies some more pain: if one peer loses the DTLS context for the other, that peer is not longer able to verify encrypted DTLS records from the other, nor is it able to decrypt that DTLS records. Additionally, that peer will also be not able, to send a proper encrypted DTLS record back to the other peer. Over the years therefore one question was raised again and again: could such a peer, which lost the DTLS context, not just send a message back in order to notify the other peer about that. The nasty point is, though this message could not be protected by encryption, it would also be possible, that an attacker creates such an unprotected message and send that with a spoofed ip-address. Therefore it doesn't work.

- [Californium issues - Handling of unknown PSK identity](https://github.com/eclipse/californium/issues/606)
- [IETF TLS mailing list - Handling of unknown PSK identity](https://mailarchive.ietf.org/arch/msg/tls/3sXyPNowGI1zn3qwTQr7ZWhIBMI/)
- [Californium issues - Handling of session errors](https://github.com/eclipse/californium/issues/1413)
- [Californium issues - Handling of session errors](https://github.com/eclipse/californium/issues/1879)

# Message Size Limits - MTU

Using UDP the message size becomes more significant than for TCP. General information may be found in [WikiPedia - IP fragmentation](https://en.wikipedia.org/wiki/IP_fragmentation). For IPv4 fragmentation is supported, but it is considered to be somehow unreliable. For IPv6 it is considered to be mostly disabled. With that, the PMTU (Path MTU - smallest MTU on the IP route/path) becomes more important. But unfortunately, Java usually have no access to the ICMP protocol in order to discover the PMTU. Anyway, that PMTU discover requires to exchange a couple of messages, maybe more, than the DTLS of CoAP exchange would require. That leaves a deployment usually in a state, where a priori information about the MTU provides a benefit. Without that, Californium can be configured to assume a MTU, auto-detect the "link-local" MTU (default without configuration), or auto-detect the "link-local" MTU and limit that MTU by a configured value.

- [DtlsConfig.DTLS_MAX_TRANSMISSION_UNIT](src/main/java/org/eclipse/californium/scandium/config/DtlsConfig.java#L428) 
- [DtlsConfig.DTLS_MAX_TRANSMISSION_UNIT_LIMIT](src/main/java/org/eclipse/californium/scandium/config/DtlsConfig.java#L442) 

If the a priori information is only available for one of both peers, then it gets important to negotiate some how the message size to be used. The same applies, if the server requires flexibility to support clients with different possibilities.

## DTLS 1.2 Record Size Limits Extension

DTLS 1.2 offers two ways to define a limit of the size for handshake record or messages.

- [RFC 6066 - Maximum Fragment Length Negotiation](https://tools.ietf.org/html/rfc6066#section-4), see [DtlsConfig.DTLS_MAX_FRAGMENT_LENGTH](src/main/java/org/eclipse/californium/scandium/config/DtlsConfig.java#L378)
- [RFC 8449 - Record Size Limit Extension ](https://tools.ietf.org/html/rfc8449), see [DtlsConfig.DTLS_RECORD_SIZE_LIMIT](src/main/java/org/eclipse/californium/scandium/config/DtlsConfig.java#L369)

Without extension, [RFC 5246 - 6.2.1.  Fragmentation](https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.1) limits the plaintext fragment length to 2^14 bytes (16K). Using [RFC 6066 - Maximum Fragment Length Negotiation](https://tools.ietf.org/html/rfc6066#section-4) enables to negotiate (always triggered by the client) 2^9, 2^10, 2^11, or 2^12 (512, 1024, 2048, 4096). For DTLS mainly the 512 and 1024 are relevant. [RFC 8449 - Record Size Limit Extension ](https://tools.ietf.org/html/rfc8449) enables the peer to negotiate a length in bytes, ranging from 64 to 2^14 (TLS 1.2 maximum, 16K, values larger than about 1024 or 1280 are not common).

If all that fails, or is not supported by both peers, [RFC 6347 - 4.1.1.1.  PMTU Issues](https://datatracker.ietf.org/doc/html/rfc6347#section-4.1.1.1) defines to reduce the message size on retransmissions as backoff strategy.

    If repeated retransmissions do not result in a response, and the
    PMTU is unknown, subsequent retransmissions SHOULD back off to a
    smaller record size, fragmenting the handshake message as
    appropriate.  This standard does not specify an exact number of
    retransmits to attempt before backing off, but 2-3 seems
    appropriate.

In Californium this number of retransmissions before using smaller messages can be configure with [DtlsConfig.DTLS_RETRANSMISSION_BACKOFF](src/main/java/org/eclipse/californium/scandium/config/DtlsConfig.java#L341), the default is half the value of [DtlsConfig.DTLS_MAX_RETRANSMISSIONS](src/main/java/org/eclipse/californium/scandium/config/DtlsConfig.java#L317).

Additional configuration values:

- [DtlsConfig.DTLS_USE_MULTI_RECORD_MESSAGES](src/main/java/org/eclipse/californium/scandium/config/DtlsConfig.java#L393)
- [DtlsConfig.DTLS_USE_MULTI_HANDSHAKE_MESSAGE_RECORDS](src/main/java/org/eclipse/californium/scandium/config/DtlsConfig.java#L398)

## DTLS 1.2 - RFC 5746 - Transport Layer Security (TLS) Renegotiation Indication Extension

Californium doesn't support renegotiation at all. Please always use full- or abbreviated-handshake.
[RFC 5746](https://tools.ietf.org/html/rfc5746) requires even for implementations, which doesn't support renegotiation to implement a minimal version of RFC 5746. With version 3.8 Californium supports now such a minimal version of RFC 5746.

The feature is configured with `DTLS.SECURE_RENEGOTIATION_MODE`. The supported values are `NONE`, `WANTED`, and `NEEDED`. The default is set to `WANTED`.

Californium itself uses a different technique to protect from misaligned application data and security contexts. It provides a `EndpointContext` for each received or send record, which enables to access the security parameters, which are exactly valid for that record. That mitigates not only the vulnerability fixed by [RFC 5746](https://tools.ietf.org/html/rfc5746) for the peer itself, it mitigates that even for new handshakes on the same ip-address.

Even with that protection, RFC 5746 is required to protect the other peers from being redirect to an other vulnerable server. If such a scenario is realistic, depends also on the used mutual authentication.

