![Californium logo](cf_64.png)

# Californium (Cf) - CoAP for Java

Eclipse Californium is a Java implementation of [RFC7252 - Constrained Application Protocol](http://tools.ietf.org/html/rfc7252) for IoT Cloud services. Thus, the focus is on scalability and usability instead of resource-efficiency
like for embedded devices. Yet Californium is also suitable for embedded JVMs.

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

The build-process is tested for jdk 7, jdk 8 and jdk 11. For jdk 7 the revapi maven-plugin is disabled, it requires at least java 8.

To generate the javadocs, add "-DcreateJavadoc=true" to the command line and set the `JAVA_HOME`.

```sh
$ mvn clean install -DcreateJavadoc=true
```

## Build jdk7 compliant

Californium 2.x can be used with java 7 or newer. If you want to build it with a jdk 7, but use also plugins which are only supported for newer jdks, the toolchain plugin could be used. That requires a toolchains configuration in "toolchains.xml" in your maven ".m2" folder

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

To support EdDSA, either java 15, or java 11 with [ed25519-java](https://github.com/str4d/ed25519-java) is required at runtime. Using java 15 to build Californium, leaves out `ed25519-java`, 
using java 11 for building, includes `ed25519-java` by default. If `ed25519-java` should **NOT** be included into the californium's jars, add `-Dno.net.i2p.crypto.eddsa=true` to maven's arguments.

```sh
$ mvn clean install -Dno.net.i2p.crypto.eddsa=true
```

In that case, it's still possible to use `ed25519-java`, if the [eddsa-0.3.0.jar](https://repo1.maven.org/maven2/net/i2p/crypto/eddsa/0.3.0/eddsa-0.3.0.jar) is provided to the classpath separately.

# Using Californium in Maven Projects

We are publishing Californium's artifacts for milestones and releases to [Maven Central](https://search.maven.org/search?q=g:org.eclipse.californium%20a:parent%20v:2.6.1).
To use the latest released version as a library in your projects, add the following dependency
to your `pom.xml` (without the dots):

```xml
  <dependencies>
    ...
    <dependency>
            <groupId>org.eclipse.californium</groupId>
            <artifactId>californium-core</artifactId>
            <version>2.6.1</version>
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
You can then simply depend on `3.0.0-SNAPSHOT`.

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

(Note: that changed from "californium.eclipse.org" on the 9th. December 2020. All 2.x demo- and plugtest-clients must therefore use the new destination "californium.eclipseprojects.io" explicitly!)

It is an instance of the [cf-plugtest-server](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-plugtest-server/2.6.1/cf-plugtest-server-2.6.1.jar) from the demo-apps.
The root resource responds with its current version.

More information can be found at [http://www.eclipse.org/californium](http://www.eclipse.org/californium) and technical details at [https://projects.eclipse.org/projects/iot.californium](https://projects.eclipse.org/projects/iot.californium).

Another interop server with a different implementation can be found at
[coap://coap.me:5683/](coap://coap.me:5683/).
More information can be found at [http://coap.me/](http://coap.me/).

# Adapter Selection

For some systems (particularly when multicasting), it may be necessary to specify/restrict californium to a particular network interface, or interfaces. This can be
 achieved by setting the `COAP_NETWORK_INTERFACES` JVM parameter to a suitable regex, for example:
 
`java -DCOAP_NETWORK_INTERFACES='.*wpan0' -jar target/cf-helloworld-server-2.6.1.jar MulticastTestServer`

# Contact

A bug, an idea, an issue? Join the [Mailing list](https://dev.eclipse.org/mailman/listinfo/cf-dev)
or create an issue here on GitHub.

# Contributing

Please check out our [contribution guidelines](CONTRIBUTING.md)
