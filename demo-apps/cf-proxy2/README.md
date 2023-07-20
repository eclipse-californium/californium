![Californium logo](../../cf_64.png)

# Californium - Example Cross Proxy 2

The ExampleCrossProxy2 demonstrates the functions of the [californium-proxy2](../../californium-proxy2) library. See [californium-proxy2 README.md](../../californium-proxy2/README.md) for more details.

## Usage

Start the proxy:
 
```sh
java -jar cf-proxy2-<version>.jar ExampleCrossProxy2 coap http
```

This starts the example cross-proxy and a co-located coap- and http-destination-server.

Start a example coap-client (same host as proxy):

```sh
java -jar cf-proxy2-<version>.jar ExampleProxy2CoapClient
```

Start a example http-client (same host as proxy):

```sh
java -jar cf-proxy2-<version>.jar ExampleProxy2HttpClient
```

To test other setups requires to edit the examples and build them on your own.

## Usage with outgoing coaps

Start the proxy:
 
```sh
java -jar cf-proxy2-<version>.jar ExampleSecureProxy2 coaps
```

This starts the example cross-proxy and a co-located coaps-destination-server.

Start a example coaps-client (same host as proxy):

```sh
java -jar cf-proxy2-<version>.jar ExampleSecureProxy2CoapClient
```

