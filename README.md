![Californium logo](cf_64.png)

# Californium (Cf) - CoAP for Java

Eclipse Californium is a Java implementation of [RFC7252 - Constrained Application Protocol](http://tools.ietf.org/html/rfc7252) for IoT Cloud services. Thus, the focus is on scalability and usability instead of resource-efficiency like for embedded devices. Yet Californium is also suitable for embedded JVMs.

More information can be found at
[http://www.eclipse.org/californium/](http://www.eclipse.org/californium/)
and [http://coap.technology/](http://coap.technology/).

# Build using Maven

You need to have a working maven installation to build Californium.
Then simply run the following from the project's root directory:

```sh
$ mvn clean install
```

Executable JARs of the examples with all dependencies can be found in the `demo-apps/run` folder.

The build-process in branch `master` is tested for jdk 7, jdk 8, jdk 11, jdk 15 and jdk 16. 
For jdk 7 the revapi maven-plugin is disabled, it requires at least java 8.

To generate the javadocs, add "-DcreateJavadoc=true" to the command line and set the `JAVA_HOME`.

```sh
$ mvn clean install -DcreateJavadoc=true
```
## Build earlier release

## !!! Since 29. October 2021 !!!
**The hostname "non-existing.host" is now existing and all builds of version and tags before that date will fail.**

To (re-)build versions before that date the unit tests must therefore be skipped.

```sh
$ mvn clean install -DskipTests
```

Earlier versions (3.0.0-Mx, 2.6.5 and before) may also fail to build with newer JDKs, especially, if java 16 is used! That is cause by the unit test dependency to a deprecated version of "mockito". If such a (re-)build is required, the unit tests must be skipped (which is in the meantime anyway required caused by the "non-existing.host").

In combination with the "non-existing.host" now existing, the build with unit test only works for the current heads of the branches `2.6.x` and `master`!

## Build jdk7 compliant

Californium 2.x and newer can be used with java 7 or newer. If you want to build it with a jdk 7, but use also plugins which are only supported for newer jdks, the toolchain plugin could be used. That requires a toolchains configuration in "toolchains.xml" in your maven ".m2" folder

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

To support EdDSA, either java 15, java 16, or java 11 with [ed25519-java](https://github.com/str4d/ed25519-java) is required at runtime. Using java 15 to build Californium, leaves out `ed25519-java`, 
using java 11 for building, includes `ed25519-java` by default. If `ed25519-java` should **NOT** be included into the californium's jars, add `-Dno.net.i2p.crypto.eddsa=true` to maven's arguments.

```sh
$ mvn clean install -Dno.net.i2p.crypto.eddsa=true
```

In that case, it's still possible to use `ed25519-java`, if the [eddsa-0.3.0.jar](https://repo1.maven.org/maven2/net/i2p/crypto/eddsa/0.3.0/eddsa-0.3.0.jar) is provided to the classpath separately.

## Run unit tests using Bouncy Castle as alternative JCE provider

With 3.0 a first, experimental support for using Bouncy Castle (1.69, bcprov-jdk15on, bcpkix-jdk15on, and, for tls, bctls-jdk15on) is implemented.

To demonstrate the basic functions, run the unit-tests using the profile `bc-tests`

```sh
$ mvn clean install -Pbc-tests
```

Supporting Bouncy Castle for the unit test uncovers a couple of differences, which required to adapt the implementation. It is assumed, that more will be found and more adaption will be required. If you find some, don't hesitate to report issues, perhaps research and analysis, and fixes. On the other hand, the project Californium will for now not be able to provide support for Bouncy Castle questions with or without relation to Californium. You may create issues, but it may be not possible for us to answer them.

On issue seems to be the `SecureRandom` generator, which shows in some environments strange CPU/time consumption.

With that, it gets very time consuming to test all combinations. Therefore, if you need a specific one, please test it on your own. If you consider, that some adaption is required, let us know by creating an issue or PR.

# Using Californium in Maven Projects

We are publishing Californium's artifacts for milestones and releases to [Maven Central](https://search.maven.org/search?q=g:org.eclipse.californium%20a:parent%20v:3.0.0).
To use the latest released version as a library in your projects, add the following dependency
to your `pom.xml` (without the dots):

```xml
  <dependencies>
    ...
    <dependency>
            <groupId>org.eclipse.californium</groupId>
            <artifactId>californium-core</artifactId>
            <version>3.0.0</version>
    </dependency>
    ...
  </dependencies>
  ...
```

##### Current Builds

You can also be bold and try out the most recent build from `master`.
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
You can then simply depend on `3.1.0-SNAPSHOT`.

# Eclipse

The project can be easily imported into a recent version of the Eclipse IDE.
Make sure to have the following before importing the Californium (Cf) projects:

* [Eclipse EGit](http://www.eclipse.org/egit/) (should be the case with every recent Eclipse version)
* [m2e - Maven Integration for Eclipse](http://www.eclipse.org/m2e/) (should be the case with every recent Eclipse version)
* UTF-8 workspace text file encoding (Preferences &raquo; General &raquo; Workspace)

Then choose *[Import... &raquo; Maven &raquo; Existing Maven Projects]* to import `californium` into Eclipse.

# IntelliJ

The project can also be imported to IntelliJ as follows:

In IntelliJ, choose *[File.. &raquo; Open]* then select the location of the cloned repository in your filesystem. IntelliJ will then automatically import all projects and resolve required Maven dependencies.

# Interop Server

A test server is running at <a href="coap://californium.eclipseprojects.io:5683/">coap://californium.eclipseprojects.io:5683/</a>

It is an instance of the [cf-plugtest-server](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-plugtest-server/3.0.0/cf-plugtest-server-3.0.0.jar) from the demo-apps.
The root resource responds with its current version.

More information can be found at [http://www.eclipse.org/californium](http://www.eclipse.org/californium) and technical details at [https://projects.eclipse.org/projects/iot.californium](https://projects.eclipse.org/projects/iot.californium).

Another interop server with a different implementation can be found at
[coap://coap.me:5683/](coap://coap.me:5683/).
More information can be found at [http://coap.me/](http://coap.me/).

# Adapter Selection

For some systems (particularly when multicasting), it may be necessary to specify/restrict californium to a particular network interface, or interfaces. This can be
 achieved by setting the `COAP_NETWORK_INTERFACES` JVM parameter to a suitable regex, for example:
 
`java -DCOAP_NETWORK_INTERFACES='.*wpan0' -jar target/cf-helloworld-server-3.0.0.jar MulticastTestServer`

# Contact

A bug, an idea, an issue? Join the [Mailing list](https://dev.eclipse.org/mailman/listinfo/cf-dev)
or create an issue here on GitHub.

# Contributing

Please check out our [contribution guidelines](CONTRIBUTING.md)
