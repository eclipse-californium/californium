![Californium logo](../cf_64.png)

# Californium (Cf) - CoAP Core

_Californium (Cf)_  is a pure Java implementation of the _Constrained Application Protocol (CoAP)_ , also known as [RFC 7252](https://tools.ietf.org/html/rfc7252). 

_Californium (Cf)_ uses an [element-connector](../element-connector) to exchange message via different transport implementations. CoAP message serialization and deserialization is implemented here, together with the protocol's state-machines.

# Usage

To exchange CoAP messages a [Endpoint](src/main/java/org/eclipse/californium/core/network/Endpoint.java) is used. That is usually implemented by a [CoapEndpoint](src/main/java/org/eclipse/californium/core/network/CoapEndpoint.java), which could be created using the [CoapEndpoint.Builder](src/main/java/org/eclipse/californium/core/network/CoapEndpoint.java#L1345-L1683). It requires an [Connector](../element-connector/src/main/java/org/eclipse/californium/elements/Connector.java) for the several transport protocols, including custom implementations.

# Client

A [Request](src/main/java/org/eclipse/californium/core/coap/Request.java) may be sent using directly an `Endpoint` or a [CoapClient](src/main/java/org/eclipse/californium/core/CoapClient.java) for more convenience.

```
...
CoapConfig.register();
UdpConfig.register();
...

CoapEndpoint endpoint = CoapEndpoint.builder().build();
endpoint.start();

Request get = Request.newGet();
get.setURI("coap://californium.eclipseprojects.io/test");

get.send(endpoint);
Response response = get.waitForResponse(10000);
...
endpoint.destroy();
```
or

```
...
CoapConfig.register();
UdpConfig.register();
...
CoapClient client = new CoapClient("coap://californium.eclipseprojects.io/test");
Response response = client.get();
...
client.shutdown();
```

Using other transport protocols requires to setup an `Endpoint` using the specific `Connector`.

```
...
CoapConfig.register();
DtlsConfig.register();
...
Configuration configuration = Configuration.getStandard();
DtlsConnectorConfig dtlsConfiguration = DtlsConnectorConfig.builder(configuration)
   .set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY)
   .setAdvancedPskStore(new AdvancedSinglePskStore("identity", "secret".getBytes()))
   .build();

CoapEndpoint endpoint = CoapEndpoint.builder()
   .setConnector(new DTLSConnector(dtlsConfiguration))
   .build();
endpoint.start();

Request get = Request.newGet();
get.setURI("coaps://californium.eclipseprojects.io/test");

get.send(endpoint);
Response response = get.waitForResponse(10000);
...
endpoint.destroy();
```

or 

```
...
CoapConfig.register();
DtlsConfig.register();
...
// some DTLS endpoint setup as above

CoapEndpoint endpoint = CoapEndpoint.builder()
   .setConnector(new DTLSConnector(dtlsConfiguration))
   .build();

EndpointManager.getEndpointManager().setDefaultEndpoint(endpoint);

CoapClient client = new CoapClient("coaps://californium.eclipseprojects.io/test");
Response response = client.get();
...
client.shutdown();
```

# Server

A [CoapServer](src/main/java/org/eclipse/californium/core/CoapServer.java) combines receiver `Endpoint`s and a tree of [Resources](src/main/java/org/eclipse/californium/core/server/resources/Resource.java). The same `Endpoint`s can be used for sending `Request` (as client) and receiving `Request`s (as server). Please keep in mind, that such CoAP role exchanges may only work, if both peers are reachable by each other. In many network setups, only one peer is reachable, the other one is only reachable on a return path (e.g. NATed). With that, the initial message exchange is still required to be initiated by a client. Follow up exchanges may use then a role exchange. After a quiet period, the client must initiated the excahnges again.
The same is also true for the TCP variants, where usually only the TCP-client connects to the TCP-server. Once the TCP connection is established, the CoAP roles may be exchanged. For DTLS that is usually similar to TCP, except DTLS implementations, which supports both DTLS roles (default for Californium's DTLS implementation Scandium).

```
...
CoapConfig.register();
UdpConfig.register();
...

CoapServer server = new CoapServer();
server.start()
...
server.destroy();
```

That creates a very simple server, listening on port 5683 for requests. It only offers the "root" resource, so only GET "coap://<host>" works.

```
...
CoapConfig.register();
UdpConfig.register();
...
CoapClient client = new CoapClient("coap://<your-host-name>");
Response response = client.get();
...
client.shutdown();
```

## Server - Add a Resource

To add a [CoapResource](src/main/java/org/eclipse/californium/core/CoapResource.java) usually at least one of the REST methods is overriden in order to provide functionality to be executed on request. [MyIpResource](src/main/java/org/eclipse/californium/core/server/resources/MyIpResource.java#L57) demonstrates, how to do that. 

```
@Override
public void handleGET(CoapExchange exchange) {

   // get request to read out details
   Request request = exchange.advanced().getRequest();
   ...
   Response response = new Response(CONTENT);
   ...
   response.setPayload(???payload???);
   ...
   exchange.respond(response);
}
```

Once you have implemented your `Resource`, it must be added to the server.

```
...
CoapConfig.register();
UdpConfig.register();
...

CoapServer server = new CoapServer();
server.add(new MyIpResource("myip", true);
server.start()
...
server.destroy();
```

With that, you can now use a GET request 

```
...
CoapConfig.register();
UdpConfig.register();
...
CoapClient client = new CoapClient("coap://<your-host-name>/myip");
Response response = client.get();
if (response != null) {
   System.out.println(response.getPayloadString());
}

...
client.shutdown();
```

and you will get a response containing your IP-address visible to the server.

## Server Resource - Asynchronous Exchange Handler

The processing of an exchange can be customized as shown above. Sometimes that processing can not be done synchronous, e.g. because a data-base access is required, which would block the executing thread for a undefined time. To support such use-cases, the `CoapExchange.respond()` may be also called from an different thread.

```
@Override
public void handleGET(final CoapExchange exchange) {
   // get request to read out details
   Request request = exchange.advanced().getRequest();
   ...
   // start asynchronous processing, passing the exchange to a result callback
   startSynchronousProcessing(new Callback() {
       @Override
       public void onResultAvailable(String payload) {
         // executed by other thread
         Response response = new Response(CONTENT);
         response.setPayload(payload);
         exchange.respond(response);
       }
   });
   // returns without calling exchange.respond();
}
```

This approach must also consider the CoAP message timings, e.g. the client would retransmit a CON request, if it doesn't receive an ACK within 2s. If the processing time exceeds that, then it's recommended to use a [Separate Response](https://datatracker.ietf.org/doc/html/rfc7252#section-5.2.2). That is achieved by calling `CoapExchange.accept()`.

```
@Override
public void handleGET(final CoapExchange exchange) {
   // get request to read out details
   Request request = exchange.advanced().getRequest();
   ...
   // valid request
   exchange.accept();
   // start asynchronous processing, passing the exchange to a result callback
   startSynchronousProcessing(new Callback() {
       @Override
       public void onResultAvailable(String payload) {
         // executed by other thread
         Response response = new Response(CONTENT);
         response.setPayload(payload);
         exchange.respond(response);
       }
   });
   // returns without calling exchange.respond();
}
```

# Getting it

You can either use  _Californium (Cf)_  binaries from Maven or you can build your own binaries from source code.

### Binaries

The most recent  _Californium_  snapshot binaries are available from the Eclipse Foundation's Maven repository.
Simply add  _Californium_  as as dependency to your Maven POM file as shown below. Don't forget to also add the definition for Eclipse's snapshot repository.

The  _Californium_  release binaries are also available via Maven Central. Thus, you will
not need to define any additional Maven repos in your POM file or Maven settings.xml in order to get release versions.

See [Californium Project Plan](https://projects.eclipse.org/projects/iot.californium/governance) for scheduled releases.

```xml
  <dependencies>
    ...
    <dependency>
            <groupId>org.eclipse.californium</groupId>
            <artifactId>californium-core</artifactId>
            <version>3.2.0</version>
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

If you want to build and install  _Californium_  from source, simply run

```sh
mvn clean install
```

in the project's root directory.

The `californium-core` folder contains the source code for the Californium-Core library.
The [demo-apps/cf-helloworld-client](../demo-apps/cf-helloworld-client) and [demo-apps/cf-helloworld-server](../demo-apps/cf-helloworld-server) folder contains some sample code illustrating how to use Californium.

Generally it's required to register the [CoapConfig.register()](src/main/java/org/eclipse/californium/core/config/CoapConfig.java) the CoAP configuration module or to provide it when using the `Configuration(ModuleDefinitionsProvider... providers)`.
For more advanced configuration options take a look at the definitions of [CoapConfig](src/main/java/org/eclipse/californium/core/config/CoapConfig.java).

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

[RFC 7252 - The Constrained Application Protocol (CoAP)](https://tools.ietf.org/html/rfc7252).

Supported extensions:
- [RFC 7641 - Observing Resources in the Constrained Application Protocol (CoAP)](https://tools.ietf.org/html/rfc7641).
- [RFC 7959 - Block-Wise Transfers in the Constrained Application Protocol (CoAP)](https://tools.ietf.org/html/rfc7959)
- [RFC 7967 - Constrained Application Protocol (CoAP) Option for No Server Response](https://tools.ietf.org/html/rfc7967)
- [RFC 8323 - CoAP (Constrained Application Protocol) over TCP, TLS, and WebSockets](https://tools.ietf.org/html/rfc8323) (Experimental, not complete, not compliant to the final RFC. Help welcome :-).)


