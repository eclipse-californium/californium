![Californium logo](../cf_64.png)

# Californium (Cf) - CoAP Core

_Californium (Cf)_  is a pure Java implementation of the _Constrained Application Protocol (CoAP)_ , also known as [RFC 7252](https://tools.ietf.org/html/rfc7252). 

_Californium (Cf)_ uses an [element-connector](https://github.com/eclipse/californium/tree/master/element-connector) to exchange message via different transport implementations. CoAP message serialization and deserialization is implemented here, together with the protocol's state-machines.

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

A [CoapServer](src/main/java/org/eclipse/californium/core/CoapServer.java) combines receiver `Endpoint`s and a tree of [Resources](src/main/java/org/eclipse/californium/core/server/resources/Resource.java). The same `Endpoint`s can be used for sending `Request` (as client) and receiving `Request`s (as server).

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

To add a [CoapResource](src/main/java/org/eclipse/californium/core/CoapResource.java) usually at least one of the REST methods is overriden in order to provide functionality to be executed on request. [MyIpResource](src/main/java/org/eclipse/californium/core/server/resources/MyIpResource.java#L57) demonstrates, how to do that. Once you have implemented your `Resource`, it must be added to the server.

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
