![Californium logo](../../cf_64.png)

# (s)NAT / LoadBalancer Simulator

In order to test NAT and LoadBalancer specific situations, this module contains a simple simulator implementation for a (s)NAT and load-balancer. It offers an API for own test-implementations, and an example applications. For very simple test scenarios, this application may be used as UDP load-balancer or IPv6 gateway to cloud-components, which doesn't offer load-balancers for UDP or IPv6.

# Download

[Eclipse Release Repository](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-nat/4.0.0-M6/cf-nat-4.0.0-M6.jar)

#Usage

Usage:

(listening on the <any>-address)

```sh
java -jar cf-nat-<version>.jar :port destination:port [destination2:port2 ...] [-r] [-x] [-tnat=<millis>] [-tlb=<millis>] [-n=<maxNatEntries>] [-d=<messageDropping%>|[-f=<messageDropping%>][-b=<messageDropping%>]] [-s=<sizeLimit>]
```

(listening on specific addresses)

```sh
java -jar cf-nat-<version>.jar localinterface:port [localinterface2:port2 ...] -- destination:port [destination2:port2 ...] [-r] [-x]  [-tnat=<millis>] [-tlb=<millis>] [-n=<maxNatEntries>] [-d=<messageDropping%>|[-f=<messageDropping%>][-b=<messageDropping%>]] [-s=<sizeLimit>]
```

The (s)NAT receives UDP messages on the local interface(s) and port(s), creates outgoing sockets for each source endpoint of the received messages, and forwards the message using the new outgoing socket (source-NAT). If the outgoing socket receives a message back, that is the "backwarded" using the local-interface and port, which received the original incoming message. The NAT entry is removed, if during the timeout (default 30s) no new message is received.

If more than one destination is given, the load-balancer is activated.
The load-balancer receives UDP messages on the local interface(s) and port(s), creates outgoing sockets for each source endpoint of the received messages and selects a destination randomly from the provided ones, and forwards the message using the new outgoing socket (source-NAT). If the outgoing socket receives a message back, that is the "backwarded" using the local-interface and port, which received the original incoming message. If the source the backwarded message is different from the destination of this NAT entry, such violations are counted. With "reverse address update" (parameter `-r`, or NAT console command `reverse (on|off)`) it is also possible, to adapt the NAT entry to that different destination.  A destination of the load-balancer is removed, if during the timeout (default 15s) no message is received back from that destination. Such removed destinations will be probed after the load-balancer timeout to test, if the destination is on again.

```sh
java -jar cf-nat-<version>.jar :5684 node1.coap.cluster:5684 node2.coap.cluster:5684 node2.coap.cluster:5784
```

Creates a (s)NAT listening on any network interfaces at UDP port 5684 (default coaps) and forwards the traffic to 3 dtls-receivers.
(Note: in this examples it's assumed, that node2.coap.cluster offers the service on port 5684 and 5784.)

```sh
java -jar cf-nat-<version>.jar [::1]:5684 127.0.0.1:5684 -- node1.coap.cluster:5684 node2.coap.cluster:5684 node2.coap.cluster:5784
```

Creates a (s)NAT listening on the Ipv6 and IPv4 loopback network interfaces at UDP port 5684 (default coaps) and forwards the traffic to 3 dtls-receivers.
(Note: in this examples it's assumed, that node2.coap.cluster offers the service on port 5684 and 5784.)

The application waits on the console input. If a empty newline is read, then the information with the current states is printed.

```
10 NAT entries, 3 destinations.
Destination: node1.coap.cluster:5684, usage: 4
Destination: node2.coap.cluster:5684, usage: 3
Destination: node2.coap.cluster:5784, usage: 3
```

Additionally these commands are supported:

- help - print this help
- info or <empty line> - list number of NAT entries and destinations
- exit or quit - stop and exit
- clear ``[n]``- drop all NAT entries, or  or drop `n` NAT entries
- reassign - reassign incoming addresses
- rebalance - reassign outgoing addresses
- spoof - emulate spoofing, assign ephemeral outgoing address
- add ``<host:port>`` - add new destination to load-balancer, e.g. "add node1.coaps.cluster:5684"
- remove ``<host:port>`` - remove destination from load-balancer
- reverse ``(on|off)`` - enable/disable reverse address updates.

## Arguments

    -r                                          : enable reverse destination address update
    -x                                          : enable DTLS filter.
    -tnat=<milliseconds>                        : timeout for nat entries. Default 30000[ms]
    -tlb=<milliseconds>                         : timeout for destination entries. Default 15000[ms]
    -n=<max-number-of-nat-entries>              : maximum number of NAT entries. Default 10000
    -d=<messageDropping%>                       : drops forward and backward messages with provided probability
    -f=<messageDropping%>                       : drops forward messages with provided probability
    -b=<messageDropping%>                       : drops backward messages with provided probability
    -s=<sizeLimit:probability%>                 : limit message size to provided value

    use -f and/or -b, if you want to test with different probabilities.

## RRC - Return Routability Check

###

In order to execute the RRC samples locally, a java runtime is required. Please follow the instructions in the [WiKi - Californium running the sandbox locally for integration tests](https://github.com/eclipse-californium/californium/wiki/Californium---running-the-sandbox-locally-for-integration-tests#requirements) how to install and test it.

If you want to run the `PlugtestServer` locally, that wiki also contains the instructions.

Once the java runtime is available, the [cf-nat - instructions](https://github.com/eclipse-californium/californium/tree/main/cf-utils/cf-nat) could be used. For testing the [Path Validation Procedure - Basic](https://tlswg.org/dtls-rrc/draft-ietf-tls-dtls-rrc.html#section-7.1) start it with:

```
java -jar cf-nat-<version>.jar :6684 localhost:5684 -tnat=5000
```

when running the `PlugtestServer` locally, or

```
java -jar cf-nat-<version>.jar -tnat=5000  :6684 californium.eclipseprojects.io:5684
```

when the [Interop-Server](https://github.com/eclipse-californium/californium/blob/main/README.md#interop-server) should be used.

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
