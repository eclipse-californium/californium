![Californium logo](../cf_64.png)

# element-connector

The element-connector is a Java socket abstraction for UDP, DTLS, TCP, etc.
It is used to modularize Californium (Cf) and add DTLS support through the
standalone Scandium (Sc) project. Further projects can add so add different
transports independently (e.g., TCP, SMS, or special sockets when running in
an optimized VM such as Virtenio's PreonVM).

Over the time, it becomes also the place for common functions, shared between other modules of Californium.
It contains some helper classes, as [SslContextUtil](src/main/java/org/eclipse/californium/elements/util/SslContextUtil.java) for loading certificates, or [Asn1DerDecoder](src/main/java/org/eclipse/californium/elements/util/Asn1DerDecoder.java) to decode common binary representations used in (D)TLS, e.g. `String Asn1DerDecoder.readCNFromDN(byte[])` to overcome the complexity of parsing the textual representation of a DN.
[StringUtil](src/main/java/org/eclipse/californium/elements/util/StringUtil.java) offers conversion between bytes and hexadecimal or base64 representations.
[Statistic](src/main/java/org/eclipse/californium/elements/util/Statistic.java) and [TimeStatistic](src/main/java/org/eclipse/californium/elements/util/TimeStatistic.java) are offering statistic functions based on value slots and counters in order to support statistics based on huge amount of samples.

Starting with version 3, the [Configuration](src/main/java/org/eclipse/californium/elements/config/Configuration.java) was moved from `californium-core` to this `element-connector` in order to be usable also for other modules as `scandium` or `element-connector-tcp-netty`.

## Maven

Usually the element-connector is already included as Maven dependency in the
Californium projects. Alternatively, use `mvn clean install` in the root
directory to build and install the artifact locally.

The Maven repositories are:

```xml
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

## Eclipse

The project also includes the project files for Eclipse. Make sure to have the
following before importing the project:

* [Eclipse EGit](http://www.eclipse.org/egit/)
* [m2e - Maven Integration for Eclipse](http://www.eclipse.org/m2e/)
* UTF-8 workspace text file encoding (Preferences &raquo; General &raquo; Workspace)

Then choose *[Import... &raquo; Git &raquo; Projects from Git &raquo; Local]*
to import `californium.element-connector` into Eclipse.

## SslContextUtil

The [SslContextUtil](src/main/java/org/eclipse/californium/elements/util/SslContextUtil.java) is one way to load certificates and private keys. And to convert them into the providers used for TLS (`SSLContext`). For DTLS [Scandium](../scandium-core#rpkx509) offers the corresponding providers.

Supported formats:

| Ending | Type | Description |
| ------ | ---- | ----------- |
| .jks | JKS | Java Key Store |
| .bks | BKS | BouncyCastle Key Store |
| .p12 | PKCS12 | [RFC7292](https://www.rfc-editor.org/rfc/rfc7292.html) |
| .pem | CRT/PEM | custom reader |
| .crt | CRT/PEM | custom reader |

Note: the CRT/PEM format contains base64 encoded credentials together with a descriptive comment.

Example for PEM:

```
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBw7lyMR21FDpCecT0bNr4oKBuYw1VdNnCB5xSS4dQrcoAoGCCqGSM49
AwEHoUQDQgAETY8Y02TZuaRUQvXnguxg6EPN7wR5vzxthmDk+6vvf6oJgBylWIU2
E3khCBkZM9Um7JCA9/kcbNezwJDzyQAnIw==
-----END EC PRIVATE KEY-----
```

You may use [lapo.it/asn1js](https://lapo.it/asn1js) to decode the content.
Please ensure, that you only provide test- or demo-credentials to that service.

That example file is loaded with `SslContextUtil.loadCredentials(String)`
passing in the filename. The returned `Credentials` contains a `private key`, and
here, also the corresponding `public key`. The current reader does not support the
encrypted versions, please use one of the `key store` formats, if encryption is required.

To load trusted certificates, either the same function `SslContextUtil.loadCredentials(String)`
may be used and the trusted certificates will then be accessed with 
`Credentials.getTrustedCertificates()`. Or use `SslContextUtil.loadTrustedCertificates(String)`.

The supported `key store` formats above are organized using an "alias-name" to access the contained credentials. E.g. in the [Demo - KeyStore](../demo-certs/certs/keyStore.jks), the alias "server" is
used to select the demo-server `private key` and `certificate-chain`. They usually use
a two level authorization, the first level to access the file at all and protected that from
unintended modifications, the second to access the `private key`s.

To load a key store (JKS, BKS, or PKCS12) and access the node's credentials, use `SslContextUtil.loadCredentials(String keyStoreUri, String alias, char[] storePassword, char[] keyPassword)`. The returned `Credentials` for the alias "server" in the demo-key-store contains then a `private key` and the corresponding server `certificate chain`. To access the trusted certificates, use `SslContextUtil.loadTrustedCertificates(String keyStoreUri, String alias, char[] storePassword)`. Though no `private key` are involved, no `keyPassword` is required.

For certificate based authentication, a peer requires:

- a `private key` in order to sign the handshakes `ServerKeyExchange` message
(server side) or the `CertificateVerify` message (client side).

- for [X509 - RFC5280](https://www.rfc-editor.org/rfc/rfc5280.html)
    - a corresponding `certificate chain`
    - a set of `trusted certificates` to verify the trust of the other peers certificates.

- for [Raw Public Key - RFC7250](https://www.rfc-editor.org/rfc/rfc7250.html)
    - a corresponding `public key`
    - a set of `trusted public keys` of the other peers.

In cases, where only the server uses a certificate to authenticate itself and authorize for the contained DNS name, only the `private key` and `certificate chain` is required on the server side, and the signing `CA certificate` must be added to the `trusted certificates` on the client side.

In order to use the loaded credentials with TLS use `SslContextUtil.createSSLContext` and provide the loaded credentials. Or use `TrustManager[] loadTrustManager(String keyStoreUri, String aliasPattern, char[] storePassword)` and `KeyManager[] loadKeyManager(String keyStoreUri, String aliasPattern, char[] storePassword, char[] keyPassword)` and use them on your own to create the required `SSLContext`.
