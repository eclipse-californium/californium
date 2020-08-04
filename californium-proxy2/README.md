# Californium - Proxy 2

CoAP [RFC 7252](https://tools.ietf.org/html/rfc7252) specifies in [5.7 Proxying](https://tools.ietf.org/html/rfc7252#section-5.7) also a proxy functionality. That contains 

-  [5.7.2 Forwarding-Proxies](https://tools.ietf.org/html/rfc7252#section-5.7.2), a generic proxy solution,
-  [5.7.3 Reverse-Proxies](https://tools.ietf.org/html/rfc7252#section-5.7.3), for specific proxies, and
-  [10. Cross-Protocol Proxying between CoAP and HTTP](https://tools.ietf.org/html/rfc7252#section-10), for mapping between http and coap.

A lot of specification, so start with the more common http and http proxies to get into it.

## Basics: HTTP proxy

A http request is processed by opening a TCP connection to the destination host-service and sending a line containing the request.

```shell
wget http://destination:8000/http-target
```

Http-request sent:

```
GET /http-target HTTP/1.1 
```

If a http proxy is used, that TCP connection is opened to the proxy-service instead of the destination host-service. The request is then sent to the proxy, that should process the request on its behalf. But the destination seems to be lost. Therefore, if the http-client sends a request to a proxy, the client adds the destination as well to the request line itself.

Http-request sent via proxy:

```
GET http://destination:8000/http-target HTTP/1.1 
```

That does the trick.

## CoAP proxy

The same happens for coap.

If the coap-request is sent directly to the destination coap-service, the destination may not be included in the uri-host and uri-port options of that request [5.10.1 URI options](https://tools.ietf.org/html/rfc7252#section-5.10.1), or, if included, these options contains the values for this destination coap-service.

Coap-request:

```
CON, MID:5446, GET, TKN:08 2c 09 b6 8c 37 6b aa, /coap-target
```

If the request is sent to a proxy, the uri-host and/or uri-port must contain the destination coap-service:

Coap-request via proxy:

```
CON, MID:18236, GET, TKN:80 e3 48 28 96 6a 8e 18, coap://destination/coap-target
```

## CoAP Cross proxy

If a proxy should only process coap-request on its behalf, then all would be as easy and simple as above, no real difference to http. If a coap-request should be translated into a http-request and vice versa, the processing may get a tick more complicated. The first question, which comes in mind, is, how should a coap-proxy know, that the coap-request it received, should be translated into http and then send to a http-server? The answer is the sames as with the destination service; that information is added to the request. CoAP offers for that a special [5.10.2 Proxy-Scheme](https://tools.ietf.org/html/rfc7252#section-5.10.2) option.

Coap2http-request via proxy using proxy-scheme:

```
CON, MID:4119, GET, TKN:d0 c0 81 bf af 8e 96 bf, coap://localhost:8000/http-target, coap.opt.proxy_scheme: http
```

[6. CoAP URIs](https://tools.ietf.org/html/rfc7252#section-6) doesn't offer all a http URI offers. For that, if required, CoAP offers also [5.10.2 Proxy-Uri](https://tools.ietf.org/html/rfc7252#section-5.10.2) option.

Coap2http-request via proxy using proxy-uri:

```
CON, MID:4121, GET, TKN:24 60 3f d0 3b 12 ef d0, coap.opt.proxy_uri: http://user@destination:8000/http-target
```

It is intended to use either the proxy-uri or the other options uri-host, uri-port, uri-path, uri-query, and proxy-scheme.

## Http2CoAP Cross proxy

Sometimes a http proxy is intended to send coap-requests. Basically that may just be done using a coap-url:

Http2coap-request sent via proxy:

```
GET coap://destination:5683/coap-target
```

Unfortunately, too many http-libraries doesn't support other schemes as http/https. Therefore [Guidelines for Mapping Implementations: http2coap](https://tools.ietf.org/html/rfc8075) describes several other variants instead.

One variant, implemented in Californium's proxy2 is to put the destination scheme at the end.

```
GET http://destination:5683/coap-target/coap:
```

# Implementing a CoAP proxy using Californium proxy2

Above it is described, that a proxy request contains just some more information about the destination service. But how is that processed with Californium?

Each message is received by a specific [Connector](https://github.com/eclipse/californium/blob/master/element-connector/src/main/java/org/eclipse/californium/elements/Connector.java) implementation, e.g. for coaps by a [DTLSConnector](https://github.com/eclipse/californium/blob/master/scandium-core/src/main/java/org/eclipse/californium/scandium/DTLSConnector.java). The coap-specific encoding and processing is then applied by a [CoapEndpoint](https://github.com/eclipse/californium/blob/master/californium-core/src/main/java/org/eclipse/californium/core/network/CoapEndpoint.java). The outcome is a [Request](https://github.com/eclipse/californium/blob/master/californium-core/src/main/java/org/eclipse/californium/core/coap/Request.java), which is delivered by a [ServerMessageDeliverer](https://github.com/eclipse/californium/blob/master/californium-core/src/main/java/org/eclipse/californium/core/server/ServerMessageDeliverer.java) to the [CoapServer](https://github.com/eclipse/californium/blob/master/californium-core/src/main/java/org/eclipse/californium/core/CoapServer.java)'s [CoapResource](https://github.com/eclipse/californium/blob/master/californium-core/src/main/java/org/eclipse/californium/core/CoapResource.java).

## Implementing a Forwarding Proxy

For a forwarding proxy that `CoapResource` is not defined by the included destination path, it's defined by the destination-scheme, so either the proxy-scheme or proxy-uri. The Proxy2 library therefore comes with a [ForwardProxyMessageDeliverer](https://github.com/eclipse/californium/blob/master/californium-proxy2/src/main/java/org/eclipse/californium/proxy2/resources/ForwardProxyMessageDeliverer.java), which does exactly that.

To translate the incoming request in an outgoing request, the Proxy2 library comes with two resources 

-  the [ProxyCoapClientResource](https://github.com/eclipse/californium/blob/master/californium-proxy2/src/main/java/org/eclipse/californium/proxy2/resources/ProxyCoapClientResource.java), for outgoing coap-requests and 
-  the [ProxyHttpClientResource](https://github.com/eclipse/californium/blob/master/californium-proxy2/src/main/java/org/eclipse/californium/proxy2/resources/ProxyHttpClientResource.java) for outgoing http-requests.

### Implementing coap2http forwarding proxy

A coap2http forward proxy could be implemented by

-  initialize the `HttpClientFactory.setNetworkConfig(config)`.
-  create a `CoapServer` and add the intended `CoapEndpoint`s to it.
-  create a `ProxyHttpClientResource`.
-  create a `ForwardProxyMessageDeliverer` providing the created `ProxyHttpClientResource`.
-  replace the `MessageDeliverer` of the `CoapServer` by the `ForwardProxyMessageDeliverer`.
-  start the `CoapServer`.

That's it. See the [BasicForwardingProxy2](https://github.com/eclipse/californium/blob/master/demo-apps/cf-proxy2/src/main/java/org/eclipse/californium/examples/basic/BasicForwardingProxy2.java).

### Implementing coap2coap forwarding proxy

That's pretty much the same as for the coap2http-proxy. Instead of initializing the `HttpClientFactory` create a [ClientSingleEndpoint](https://github.com/eclipse/californium/blob/master/californium-proxy2/src/main/java/org/eclipse/californium/proxy2/ClientSingleEndpoint.java) and use that for a `ProxyCoapClientResource` instead of a `ProxyHttpClientResource`.

## Implementing a Reverse Proxy

Reverse proxies may come with very specific implementations. Simple ones use just a fixed outgoing request for a incoming one. For such simple reverse proxy, the proxy2 library offers a [ProxyCoapResource.createReverseProxy](https://github.com/eclipse/californium/blob/master/californium-proxy2/src/main/java/org/eclipse/californium/proxy2/resources/ProxyCoapResource.java) function.

To create a simple reverse proxy, 

-  initialize the `HttpClientFactory.setNetworkConfig(config)`, or
-  create a `ClientSingleEndpoint`, depending on the intended outgoing protocol.
   Or both, if both should be supported.
-  create a `CoapServer` and add the intended `CoapEndpoint`s to it.
-  create a `ProxyHttpClientResource`.
-  create a reverse-proxy resources using `ProxyCoapResource.createReverseProxy`.
-  add that resource to the `CoapServer`.
-  start the `CoapServer`.

That's it. See the [BasicReverseProxy2](https://github.com/eclipse/californium/blob/master/demo-apps/cf-proxy2/src/main/java/org/eclipse/californium/examples/basic/BasicReverseProxy2.java).

## Implementing a specialized Reverse Proxy

Reverse proxies may vary a lot. Some reverse proxies may just implement their own `CoapResource` other may use some parts of the library. To better understand, which function may be used, see 
That's it. See the e.g. [ProxyCoapClientResource.handleRequest()](https://github.com/eclipse/californium/blob/master/californium-proxy2/src/main/java/org/eclipse/californium/proxy2/resources/ProxyCoapClientResource.java#L76)

1.  `InetSocketAddress exposedInterface = translator.getExposedInterface(incomingRequest);` identify the exposed interface this request is received. Assuming virtualization, Containers, and clusters, the exposed interface may be only available, if it's external configured. If it's not possible to determine it, just return `null`. 
2.  `URI destination = translator.getDestinationURI(incomingRequest, exposedInterface);` get the destination. For the simple reverse proxies, this method is overridden and returns the fixed destination.

3  `Request outgoingRequest = translator.getRequest(destination, incomingRequest);` create the outgoing request.

If the general processing in `ProxyCoapClientResource` works also for the special case, the simplest way would be to use a special `Coap2CoapTranslator` or `Coap2HttpTranslator`, which overrides the functions to adapt them.

## Implementing a http2coap forwarding proxy

A http2coap forward proxy could be implemented by

-  initialize a `ClientSingleEndpoint` for outgoing request.
-  create a `ProxyHttpServer`.
-  create a `ProxyCoapClientResource` using the `ClientSingleEndpoint`.
-  create a `ForwardProxyMessageDeliverer` providing the created `ProxyCoapClientResource`.
-  replace the `MessageDeliverer` of the `CoapServer` by the `ForwardProxyMessageDeliverer`.
-  start the `ProxyHttpServer`.

See the [BasicHttpForwardingProxy2](https://github.com/eclipse/californium/blob/master/demo-apps/cf-proxy2/src/main/java/org/eclipse/californium/examples/basic/BasicHttpForwardingProxy2.java).

# Implementing a CoAP server with co-located proxy-server

Until here the things should have been not too complicated. But that starts with mixed servers, when the coap-server and the proxy-server are co-located. The difficulty, especially with reverse-proxies, is the ambiguity in interpreting the requests. If resources are either selected by the uri-path or by the destination scheme, then it may result in unintended processing. The specification assumes, that a server is able to know it's exposed address in order to determine, if the request is sent to the coap-server or the co-located proxy-server. But with the server-side virtualization and containers, that may get very hard. The proxy2 library offers some function for such mixed servers, but if such a mixed server works proper, is the responsibility of that mixed server.

-  `ForwardProxyMessageDeliverer` offers also a constructor with a root-`Resource` and a `CoapUriTranslator` translator. The root-`Resource` is required to select a `Resource` using the uri-path, and the translator could be customized to select the request to be forwarded.

-  `ForwardProxyMessageDeliverer` offers a set of exposed service addresses in order to configure them instead of detect them. 

