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

# Demo Certificates

Scandium's test cases and examples refer to Java key stores containing private and public keys. These key stores are provided by the `demo-certs` module. Please refer to the documentation of that module for more information regarding how to create your own certificates.
