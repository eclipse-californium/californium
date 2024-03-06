![Californium logo](cf_64.png)

# Feature Branch: Return Routability Check (RRC)

This feature branch is a first and experimental implementation of 
[Return Routability Check for DTLS 1.2 and DTLS 1.3](https://tlswg.org/dtls-rrc/draft-ietf-tls-dtls-rrc.html).

The feature will prevent amplification attacks using spoofing source addresses of messages with [RFC 9146, Connection Identifier for DTLS 1.2](https://www.rfc-editor.org/info/rfc9146).

When a peer receives a DTLS CID record with an change ip-endpoint, the next outgoing message may trigger a [Path Validation Procedure - Basic](https://tlswg.org/dtls-rrc/draft-ietf-tls-dtls-rrc.html#section-7.1), if the size of the outgoing message exceeds the incoming message by configurable `DTLS.RETURN_ROUTABILITY_CHECK_THRESHOLD`. An application may also decide to trigger such a [Path Validation Procedure - Basic](https://tlswg.org/dtls-rrc/draft-ietf-tls-dtls-rrc.html#section-7.1) by using `KEY_RETURN_ROUTABILITY_CHECK` endpoint-context attribute with value `TRUE`.

## Early Interop Tests for Return Routability Check (RRC)

In order to test the interoperability , you may either use your own [PlugtestServer - download](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-plugtest-server/3.11.0-RRC-0/cf-plugtest-server-3.11.0-RRC-0.jar) or use the [Interop-Server](#interop-server).

To simulate ip-endpoint changes, the [cf-nat - download](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-nat/3.11.0-RRC-0/cf-nat-3.11.0-RRC-0.jar) may be used.

And as client, the [Cf-Browser - download](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-browser/3.11.0-RRC-0/cf-browser-3.11.0-RRC-0.jar) may be used.

## Installation and Run Components Locally

In order to execute the samples locally, a java runtime is required. Please follow the instructions in the [WiKi - Californium running the sandbox locally for integration tests](https://github.com/eclipse-californium/californium/wiki/Californium---running-the-sandbox-locally-for-integration-tests#requirements) how to install and test it.

If you want to run the `PlugtestServer` locally, that wiki also contains the instructions.

Once the java runtime is available, the [cf-nat - instructions](https://github.com/eclipse-californium/californium/tree/main/cf-utils/cf-nat) could be used. For testing the [Path Validation Procedure - Basic](https://tlswg.org/dtls-rrc/draft-ietf-tls-dtls-rrc.html#section-7.1) start it with:

```
java -jar cf-nat-<version>.jar :6684 localhost:5684 -tnat=5000
```

when running the `PlugtestServer` locally, or

```
java -jar cf-nat-<version>.jar -tnat=5000  :6684 californium.eclipseprojects.io:5684
```

when the [Interop-Server](#interop-server) should be used.

The NAT will timeout the ip-routes after 5s without traffic. Therefore, if you wait a little longer before sending the next message, the server will receive the message via the new ip-endpoint mapping and will detect that as ip-endpoint change.

To use the `Cf-Browser` requires to install [javafx](https://gluonhq.com/products/javafx/) additionally. Please follow the [Cf-Browser - instruction](https://github.com/eclipse-californium/californium.tools/tree/main/cf-browser) for installation.

(In short: download the javafx SDK for your platform, uncompress it and copy the path to the contained `lib` folder in order to use it for the CLI below.)

To use it, please start it with:

```
java --module-path <path-to>/javafx-sdk-???/lib --add-modules javafx.controls,javafx.fxml -jar cf-browser-<version>.jar --cid-length=4 coaps://localhost:6684/rrc
```

(`<path-to>` according your local path of the `javafx-sdk-???/lib` folder.)

That will send the messages via the NAT (`localhost:6684`) to the `PlugtestServer`, which is used as destination for the NAT, either `localhost:5684` or `californium.eclipseprojects.io:5684`.

The resource `rrc` will force a return routability check even for small responses. The `PlugtestServer` uses a small blocksize of 64 bytes and with that the default amplification threshold of 3.0 is hard to reach.

## Simulate Spoof Attack (Amplification Attack)

One possible [attack scenario](https://tlswg.org/dtls-rrc/draft-ietf-tls-dtls-rrc.html#section-6.1) considered is based on manipulating the source address. Without using [RFC 9146, Connection Identifier for DTLS 1.2](https://www.rfc-editor.org/info/rfc9146) this causes a MAC violation and is filtered out on receiving and processing that message within the DTLS layer. With CID the still valid content of the message could be processed, but the wrong address can not be distinguished from an usual address change caused by a NAT or something similar. If the processing of the message results in a large response message, then this maybe misused for DDoS attacks. Therefore [Path Validation Procedure - Basic](https://tlswg.org/dtls-rrc/draft-ietf-tls-dtls-rrc.html#section-7.1) checks with a small message, if the new route is valid.

If the tool from the section before are still running, then just type

```
spoof
```

into the CLI of the NAT. The next message will be send with an ephemeral outgoing address. When the server then sends the "path-challenge" it doesn't receive an answer and times out the check without sending the (large) application response.

# Californium (Cf) - CoAP for Java

Eclipse Californium is a Java implementation of [RFC7252 - Constrained Application Protocol](http://tools.ietf.org/html/rfc7252) for IoT Cloud services. Thus, the focus is on scalability and usability instead of resource-efficiency like for embedded devices. Yet Californium is also suitable for embedded JVMs.

More information can be found at
[http://eclipse.dev/californium/](http://eclipse.dev/californium/)
and [http://coap.technology/](http://coap.technology/).

Like to help improving Californium? Then consider to [contribute](#contributing).

# Build using Maven

You need to have a working maven installation to build Californium.
Then simply run the following from the project's root directory:

```sh
$ mvn clean install
```

Executable JARs of the examples with all dependencies can be found in the `demo-apps/run` folder.

The build-process in branch `main` is tested for jdk8, jdk 11, jdk 17 and jdk 21. 

To generate the javadocs, add "-DcreateJavadoc=true" to the command line and set the `JAVA_HOME`.

```sh
$ mvn clean install -DcreateJavadoc=true
```

```sh
$ mvn clean install -DuseToolchainJavadoc=true
```

## Build with EdDSA support

To support EdDSA requires java 17 (or newer). Earlier versions of Californium
also supported to use [ed25519-java](https://github.com/str4d/ed25519-java) at runtime, but that library seems to be not
maintained for long and therefore the support in Californium has been removed.

## Run unit tests using Bouncy Castle as alternative JCE provider

With 3.0 a first, experimental support for using Bouncy Castle (starting with version 1.69, bcprov-jdk15on, bcpkix-jdk15on, and, for tls, bctls-jdk15on) is implemented. Version 4.0 bc version 1.78.1 gets supported.

To demonstrate the basic functions, run the unit-tests using the profile `bc-tests`

```sh
$ mvn clean install -Pbc-tests
```

Supporting Bouncy Castle for the unit test uncovers a couple of differences, which required to adapt the implementation. It is assumed, that more will be found and more adaption will be required. If you find some, don't hesitate to report issues, perhaps research and analysis, and fixes. On the other hand, the project Californium will for now not be able to provide support for Bouncy Castle questions with or without relation to Californium. You may create issues, but it may be not possible for us to answer them.

On issue seems to be the `SecureRandom` generator of BC. Dependent on the runtime environment, that is based on `SecureRandom.getInstanceStrong()`, which has blocking behaviour by default. If the platform your application runs on, has not enough entropy to start the `SecureRandom`, BC waits until that gets available. In common cases, that starts quite fast, but in some cases, that takes up to 60s (and more).

One option to overcome that on some linux variants is using `rng-tools`. That may help to provide more entropy.

A second option o overcome that is to setup `CALIFORNIUM_JCE_PROVIDER` using the value `BC_NON_BLOCKING_RANDOM` instead of `BC`. The `JceProviderUtil` then adapts `SecureRandom` to use a, maybe weaker, non-blocking `SecureRandom`. If that works, depends unfortunately on your platform, so especially for Android, that may not work. In that cases, please use `BC` as `CALIFORNIUM_JCE_PROVIDER` and configure "securerandom.strongAlgorithms" ahead with

```
Security.setProperty("securerandom.strongAlgorithms", "<your-android-algorithm>");
```

according your android variant. That may require some analysis by you.

With that, it gets very time consuming to test all combinations. Therefore, if you need a specific one, please test it on your own. If you consider, that some adaption is required, let us know by creating an issue or PR.

# Using Californium in Maven Projects

We are publishing Californium's artifacts for milestones and releases to [Maven Central](https://search.maven.org/search?q=g:org.eclipse.californium%20a:parent%20v:4.0.0-M3).
To use the latest released version as a library in your projects, add the following dependency
to your `pom.xml` (without the dots `...`):

```xml
  <dependencies>
    ...
    <dependency>
            <groupId>org.eclipse.californium</groupId>
            <artifactId>californium-core</artifactId>
            <version>3.13.0</version>
    </dependency>
    ...
  </dependencies>
  ...
```

or

```xml
  <dependencies>
    ...
    <dependency>
            <groupId>org.eclipse.californium</groupId>
            <artifactId>californium-core</artifactId>
            <version>4.0.0-M3</version>
    </dependency>
    ...
  </dependencies>
  ...
```

**Note:** the API of milestone release `4.0.0-M3` isn't stable yet.

##### Current Builds

You can also be bold and try out the most recent build from `main`.
However, we are not publishing those to Maven Central but to Californium's project repository at Eclipse only.
You will therefore need to add the Eclipse Repository to your `pom.xml` first:

```
  <repositories>
    ...
    <repository>
      <id>repo.eclipse.org</id>
      <name>Californium Repository</name>
      <url>https://repo.eclipse.org/content/repositories/californium/</url>
    </repository>
    ...
  </repositories>
```
You can then simply depend on `4.0.0-SNAPSHOT`.

# Eclipse

The project can be easily imported into a recent version of the Eclipse IDE.
Make sure to have the following before importing the Californium (Cf) projects:

* [Eclipse EGit](http://www.eclipse.org/egit/) (should be the case with every recent Eclipse version)
* [m2e - Maven Integration for Eclipse](http://www.eclipse.org/m2e/) (should be the case with every recent Eclipse version)
* UTF-8 workspace text file encoding (Preferences &raquo; General &raquo; Workspace)

Then choose *[Import... &raquo; Maven &raquo; Existing Maven Projects]* to import `californium - parent` together with all sub-modules into Eclipse.

# IntelliJ

The project can also be imported to IntelliJ as follows:

In IntelliJ, choose *[File.. &raquo; Open]* then select the location of the cloned repository in your filesystem. IntelliJ will then automatically import all projects and resolve required Maven dependencies.

# Interop Server

A test server is running at <a href="coap://californium.eclipseprojects.io:5683/">coap://californium.eclipseprojects.io:5683/</a>

It is an instance of the [cf-plugtest-server](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-plugtest-server/4.0.0-M3/cf-plugtest-server-4.0.0-M3.jar) from the demo-apps.
The root resource responds with its current version.

For a preview to the [Return Routability Check for DTLS 1.2 and DTLS 1.3](https://tlswg.org/dtls-rrc/draft-ietf-tls-dtls-rrc.html) experimental support, please read [feature/rrc - branch](https://github.com/eclipse-californium/californium/tree/feature/rrc).

**Please note:**
The server is intended to test the interoperability of CoAP and DTLS 1.2. Data sent to that server is typically "Hello world". The data is public visible to all other users and is removed on any restart. Please don't send data, which requires "data privacy", the sandbox server is not intended for such usage. 

More information can be found at [http://www.eclipse.org/californium](http://www.eclipse.org/californium) and technical details at [https://projects.eclipse.org/projects/iot.californium](https://projects.eclipse.org/projects/iot.californium).

Another interop server with a different implementation can be found at
[coap://coap.me:5683/](coap://coap.me:5683/).
More information can be found at [http://coap.me/](http://coap.me/).

## Interop Server - (D)TLS Support

The server uses the [x509 Demo Certificates](/demo_certs), which are usually recreated and replaced once a year.
And the PSK credentials:

| Identity | Secret | Remark |
| -------- | ------ | ------ |
| "Client_identity" | "secretPSK" | openssl defaults |
| "password" | "sesame" | ETSI Plugtest test spec |
| Regex "`cali\..*`" | ".fornium" | Wildcard Identity for plugtest |
| Regex "`^[^@]{8,}@.{8,}$`" | "secret" | Wildcard Identity for hono-identites |

**Note:** TLS supports only the x509 Demo Certificates. To enable a client to use x509, please add the below CA certificate to it's trusts.

```
Bag Attributes
    friendlyName: C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-ca
subject=CN = cf-ca, OU = Californium, O = Eclipse IoT, L = Ottawa, C = CA

issuer=CN = cf-root, OU = Californium, O = Eclipse IoT, L = Ottawa, C = CA

-----BEGIN CERTIFICATE-----
MIICDDCCAbKgAwIBAgIIPKO8L7vZoqAwCgYIKoZIzj0EAwIwXDEQMA4GA1UEAxMH
Y2Ytcm9vdDEUMBIGA1UECxMLQ2FsaWZvcm5pdW0xFDASBgNVBAoTC0VjbGlwc2Ug
SW9UMQ8wDQYDVQQHEwZPdHRhd2ExCzAJBgNVBAYTAkNBMB4XDTIzMTAyNjA4MDgx
NVoXDTI1MTAyNTA4MDgxNVowWjEOMAwGA1UEAxMFY2YtY2ExFDASBgNVBAsTC0Nh
bGlmb3JuaXVtMRQwEgYDVQQKEwtFY2xpcHNlIElvVDEPMA0GA1UEBxMGT3R0YXdh
MQswCQYDVQQGEwJDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLCbJjxIS4hI
AnRFTlx23gkd4zyFd50zdpTnoUPz19oQ1o1youavC5Go9vrYoWxyx+zpph8T4brB
C/mZGIgPVMOjYDBeMB0GA1UdDgQWBBSxVzoI1TL87++hsUb9vQwqODzgUTALBgNV
HQ8EBAMCAQYwDwYDVR0TBAgwBgEB/wIBATAfBgNVHSMEGDAWgBTqNhC1fqOTsHRn
IVZ9OabfWsxpcTAKBggqhkjOPQQDAgNIADBFAiBSEn3egc31JhhHTVYi5uhl0t4d
ewujkEmwzBuruzf/xAIhAK/fXy2tsNoyLitFQ97x6LYV25jKmLKUlhL2mC/PwQdO
-----END CERTIFICATE-----
```

## Interop Server - OSCORE Support

The server has a resource only accessible using OSCORE under "/oscore". It is configured with the following security material (client side):

```
Master Secret: 0x0102030405060708090a0b0c0d0e0f10 (16 bytes)
Master Salt:   0x9e7ca92223786340 (8 bytes)
Sender ID:     0x01 (1 byte)
Recipient ID:  0x02 (1 byte)
ID Context:    0x37cbf3210017a2d3 (8 bytes)
(See up to date parameters in "/oscoreInfo" resource)
```

Note that the server supports running the Appendix B.2 context rederivation procedure. This is necessary as requests from new clients would otherwise be considered replays (as the server's replay window is filled up from earlier clients). To access this resource without using the Appendix B.2 procedure, an appropriate Sender Sequence Number to use and the current ID Context can be retrieved from the resource "/oscoreInfo" using plain CoAP.

Currently Californium's OSCORE supports the following algorithms:

OSCORE Encryption:
- AES_CCM_16_64_128, id 10
- AES_CCM_64_64_128, id 12
- AES_CCM_16_128_128, id 30
- AES_CCM_64_128_128, id 32
- AES_CCM_16_64_256, id 11
- AES_CCM_64_64_256, id 13
- AES_CCM_16_128_256, id 31
- AES_CCM_64_128_256, id 33
- AES_GCM_128, id 1
- AES_GCM_192, id 2
- AES_GCM_256, id 3
- CHACHA20_POLY1305, id 24

OSCORE Key Derivation:
- HKDF_HMAC_SHA_256, id -10 
- HKDF_HMAC_SHA_512, id -11

For detailed information about the algorithms see the [COSE Algorithms IANA registry](https://www.iana.org/assignments/cose/cose.xhtml#algorithms).

## Interop Server - MyContext

The interop-server supports also a "mycontext" resource. The response contains the information about the client on the server side.

Examples:

```
> coap-client -p 15683 -m GET coap://californium.eclipseprojects.io/mycontext

ip: 2a02:????:915b
port: 15683
server: Cf 4.0.0-M3
```

```
> coap-client -p 15684 -m GET -u Client_identity -k secretPSK coaps://californium.eclipseprojects.io/mycontext

ip: 2a02:????:915b
port: 15684
peer: Client_identity
cipher-suite: TLS_PSK_WITH_AES_128_CCM_8
session-id: 3BBC6EBAAA4F4A4717EEC8FF2C3FB1CFC4C9C89E9807EB0F1C0CDC11C6D9110C
read-cid: 1CF2CC41B37E
write-cid: 
secure-renegotiation: true
ext-master-secret: true
newest-record: true
message-size-limit: 1343
server: Cf 4.0.0-M3
```

`ip` and `port` may be used to detect some NATs on the ip-route. If the `port:` in the response differs from the provided port in the cli (`-p`), then that's a first indication of some NAT. If a client send a new request a couple of minutes later and `ip` or `port` are changing, then that may also indicate a NAT. If the client uses DTLS without the Connection ID extension (no `read-cid`), then the request may timeout. In that case, try to use CoAP without encryption to see,  if the `ip` or `port` changes.

# Adapter Selection

For some systems (particularly when multicasting), it may be necessary to specify/restrict californium to a particular network interface, or interfaces. This can be
 achieved by setting the `COAP_NETWORK_INTERFACES` JVM parameter to a suitable regex, for example:
 
`java -DCOAP_NETWORK_INTERFACES='.*wpan0' -jar target/cf-helloworld-server-4.0.0-M3.jar MulticastTestServer`

# Contact

A bug, an idea, an issue? Join the [Mailing list](https://dev.eclipse.org/mailman/listinfo/cf-dev)
or create an issue here on GitHub.

# Contributing

Please check out our [contribution guidelines](CONTRIBUTING.md)

There are a couple of [enhancement issues](https://github.com/eclipse-californium/californium/issues?q=is%3Aissue+label%3Ahibernate), which have been closed for longer inactivity. Maybe, if you like to help and spend some time, you will be welcome.
