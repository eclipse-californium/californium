![Californium logo](../../cf_64.png)

# (s)NAT / LoadBalancer Simulator

In order to test NAT and LoadBalancer specific situations, this module contains a simple simulator implementation for a (s)NAT and load-balancer. It offers an API for own test-implementations, and an example applications. For very simple test scenarios, this application may be used as UDP load-balancer or IPv6 gateway to cloud-components, which doesn't offer load-balancers for UDP or IPv6.

# Download

[Eclipse Release Repository](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-nat/3.10.0/cf-nat-3.10.0.jar)

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

