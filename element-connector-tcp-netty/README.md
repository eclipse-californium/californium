![Californium logo](../cf_64.png)

# element-connector-tcp-netty

The _element connector tcp netty_  is a transport layer for [RFC 8323 - CoAP over TCP](https://tools.ietf.org/html/rfc8323) based on the common [netty.io](https://github.com/netty/netty) library. 

It is still experimental and based on a early draft version of that RFC.

# Usage

In order to provide TCP/TLS specific configuration, the definitions of [TcpConfig](../element-connector/src/main/java/org/eclipse/californium/elements/config/TcpConfig.java) are used. These definitions are included in the [element-connector](../element-connector) in order to be able to use TCP as optional library only at runtime. See 
[cf-cli-tcp-netty](../cf-utils/cf-cli-tcp-netty) for a client example.

## Client

A client may use a [TcpClientConnector](src/main/java/org/eclipse/californium/elements/tcp/netty/TcpClientConnector.java) or [TlsClientConnector](src/main/java/org/eclipse/californium/elements/tcp/netty/TlsClientConnector.java) and provide that as `Connector` to the `CoapEndpoint`. Once the connection is established, the coap-role (coap-client or coap-server) may be exchanged.

## Server

A server may use a [TcpServerConnector](src/main/java/org/eclipse/californium/elements/tcp/netty/TcpServerConnector.java) or [TlsServerConnector](src/main/java/org/eclipse/californium/elements/tcp/netty/TlsServerConnector.java) and provide that as `Connector` to the `CoapEndpoint`. Once the connection is accpeted, the coap-role (coap-client or coap-server) may be exchanged.

### Building from Source

If you want to build and install  _element connector tcp netty_  from source, simply run

```sh
mvn clean install
```

in the project's root directory.

The `element-connector-tcp-netty` folder contains the source code for the `element-connector-tcp-netty` library.

Generally it's required to register the [TcpConfig.register()](../element-connector/src/main/java/org/eclipse/californium/elements/config/TcpConfig.java) the TCP/TLS configuration module or to provide it when using the `Configuration(ModuleDefinitionsProvider... providers)`.
For more advanced configuration options take a look at the definitions of [TcpConfig](../element-connector/src/main/java/org/eclipse/californium/elements/config/TcpConfig.java).

# Eclipse

The project also includes the project files for Eclipse. Make sure to have the
following before importing the Californium (Cf) project:

* [Eclipse EGit](http://www.eclipse.org/egit/)
* [m2e - Maven Integration for Eclipse](http://www.eclipse.org/m2e/)
* UTF-8 workspace text file encoding (Preferences &raquo; General &raquo; Workspace)

Then choose *[Import... &raquo; Git &raquo; Projects from Git &raquo; Local]*
to import Californium's parent module and all sub-modules into Eclipse.

# Supported Features

## Supported RFCs

- [RFC 8323 - CoAP (Constrained Application Protocol) over TCP, TLS, and WebSockets](https://tools.ietf.org/html/rfc8323) (Experimental, not complete, not compliant to the final RFC. Help welcome :-).)

