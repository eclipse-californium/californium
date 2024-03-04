![Californium logo](cf_64.png)

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

The build-process in branch `main` is tested for jdk 7, jdk 8, jdk 11 and jdk 17. 
For jdk 7 the revapi maven-plugin is disabled, it requires at least java 8.

To generate the javadocs, add "-DcreateJavadoc=true" to the command line and set the `JAVA_HOME`.

```sh
$ mvn clean install -DcreateJavadoc=true
```
## Build earlier release

## !!! Since 29. October 2021 !!!
**The hostname "non-existing.host" is now existing and all builds of version and tags before that date will fail the tests. Therefore use -DskipTests**

To (re-)build versions before that date the unit tests must therefore be skipped.

```sh
$ mvn clean install -DskipTests
```

Earlier versions (3.0.0-Mx, 2.6.5 and before) may also fail to build with newer JDKs, especially, if java 17 is used! That is cause by the unit test dependency to a deprecated version of "mockito". If such a (re-)build is required, the unit tests must be skipped (which is in the meantime anyway required caused by the "non-existing.host").

In combination with the "non-existing.host" now existing, the build with unit test only works for the current heads of the branches `2.6.x`, `2.7.x`, `2.8.x` and `main`!

## Build jdk7 compliant

Californium 2.x and newer can be used with java 7 or newer. In order to use plugins,
which are only supported for newer jdks, the `--release` option is used (requires java 9 or newer).

If you want to build it with a jdk 7, the toolchain plugin could be used, but requires
manually remove the `maven.compiler.release` property in the pom.xml. That requires
also a toolchains configuration in "toolchains.xml" in your maven ".m2" folder

```xml
<?xml version="1.0" encoding="UTF8"?>
<toolchains>
	<!-- JDK toolchains -->
	<toolchain>
		<type>jdk</type>
		<provides>
			<version>1.7</version>
		</provides>
		<configuration>
			<jdkHome>path..to..jdk7...home</jdkHome>
		</configuration>
	</toolchain>
</toolchains>
```

To use the jdk7 toolchain, add "-DuseToolchain=true" to the command line.

```sh
$ mvn clean install -DuseToolchain=true
```

To use the jdk7 toolchain and create javadocs, add "-DuseToolchainJavadoc=true" to the command line (`JAVA_HOME` is not required).

```sh
$ mvn clean install -DuseToolchainJavadoc=true
```

## Build with jdk11 and EdDSA support

To support EdDSA, either java 17 or java 11 with [ed25519-java](https://github.com/str4d/ed25519-java) is required at runtime. Using java 17 (or newer) to build Californium, leaves out `ed25519-java`, using java 11 for building, includes `ed25519-java` by default. If `ed25519-java` should **NOT** be included into the californium's jars, add `-Dno.net.i2p.crypto.eddsa=true` to maven's arguments.

```sh
$ mvn clean install -Dno.net.i2p.crypto.eddsa=true
```
*Note*: if "-DuseToolchain=true" is used and the actual jdk to build is java 11, you must disable the i2p eddsa support as well.
 
```sh
# java 11 with java 7 toolchain
$ mvn clean install -DuseToolchain=true -Dno.net.i2p.crypto.eddsa=true
```

In that case, it's still possible to use `ed25519-java`, if the [eddsa-0.3.0.jar](https://repo1.maven.org/maven2/net/i2p/crypto/eddsa/0.3.0/eddsa-0.3.0.jar) is provided to the classpath separately.

*Note:* using the oracle build 28 of openjdk 11 uncovers, that calling `EdDSAEngine.engineSetParameter(null)` fails with `ǸullPointerException` instead of `InvalidAlgorithmParameterException`. That causes to fail the verification of the signature at all. Using the aptopen build seems not to call `EdDSAEngine.engineSetParameter(null)` and therefore works.

[ed25519-java](https://github.com/str4d/ed25519-java) seems to be not longer maintained. It's therefore recommended to update to newer jdks (e.g. 17) or to use Bouncy Castle (see next section, even if the Bouncy Castle support is experimental).

## Run unit tests using Bouncy Castle as alternative JCE provider

With 3.0 a first, experimental support for using Bouncy Castle (version 1.69, bcprov-jdk15on, bcpkix-jdk15on, and, for tls, bctls-jdk15on) is implemented. With 3.3 the tests are using the updated version 1.70 (for tls also  bcutil-jdk15on is used additionally), with 3.8 version 1.72, with 3.9 version 1.74,
and with 3.10 to version 1.77.

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

We are publishing Californium's artifacts for milestones and releases to [Maven Central](https://search.maven.org/search?q=g:org.eclipse.californium%20a:parent%20v:3.10.0).
To use the latest released version as a library in your projects, add the following dependency
to your `pom.xml` (without the dots):

```xml
  <dependencies>
    ...
    <dependency>
            <groupId>org.eclipse.californium</groupId>
            <artifactId>californium-core</artifactId>
            <version>3.10.0</version>
    </dependency>
    ...
  </dependencies>
  ...
```

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
You can then simply depend on `3.11.0-SNAPSHOT`.

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

It is an instance of the [cf-plugtest-server](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-plugtest-server/3.10.0/cf-plugtest-server-3.10.0.jar) from the demo-apps.
The root resource responds with its current version.

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

Note: TLS supports only the x509 Demo Certificates.

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

Currently Californium's OSCORE supports following algorithms:

OSCORE Encryption:
- AES_CCM_16_64_128, id 10
- AES_CCM_64_64_128, id 12
- AES_CCM_16_128_128, id 30
- AES_CCM_64_128_128, id 32

OSCORE Key Rederivation:
- HKDF_HMAC_SHA_256, id -10 
- HKDF_HMAC_SHA_512, id -11

# Adapter Selection

For some systems (particularly when multicasting), it may be necessary to specify/restrict californium to a particular network interface, or interfaces. This can be
 achieved by setting the `COAP_NETWORK_INTERFACES` JVM parameter to a suitable regex, for example:
 
`java -DCOAP_NETWORK_INTERFACES='.*wpan0' -jar target/cf-helloworld-server-3.10.0.jar MulticastTestServer`

# Contact

A bug, an idea, an issue? Join the [Mailing list](https://dev.eclipse.org/mailman/listinfo/cf-dev)
or create an issue here on GitHub.

# Contributing

Please check out our [contribution guidelines](CONTRIBUTING.md)

There are a couple of [enhancement issues](https://github.com/eclipse-californium/californium/issues?q=is%3Aissue+label%3Ahibernate), which have been closed for longer inactivity. Maybe, if you like to help and spend some time, you will be welcome.
