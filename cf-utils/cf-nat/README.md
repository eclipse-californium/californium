# (s)NAT / LoadBalancer Simulator

In order to test NAT and LoadBalancer specific situations, this module contains a simple simulator implementation for a (s)NAT and/or load-balancer. It offers an API for own test-implementations, and an example applications.

Usage:

```shell
java -jar cf-nat-<version>.jar [localinterface]:port destination:port [destination2:port2 ...] [-r] [-d<messageDropping%>|[-f<messageDropping%>][-b<messageDropping%>]] [-s<sizeLimit>]
```

The (s)NAT receives UDP messages on the local interface and port, creates outgoing sockets for each source endpoint of the received messages, and forwards the message using the new outgoing socket (source-NAT). If the outgoing socket receives a message back, that is the "backwarded" using the local-interface and port.

If more than one destination is given, the load-balancer is activated.
The load-balancer receives UDP messages on the local interface and port, creates outgoing sockets for each source endpoint of the received messages and selects a destination randomly from the provided ones, and forwards the message using the new outgoing socket (source-NAT). If the outgoing socket receives a message back, that is the "backwarded" using the local-interface and port. If the source the backwarded message is different from the destination of this NAT entry, such violations are counted. With "reverse address update" (parameter `-r`, or NAT console command `reverse (on|off)`) it is also possible, to adapt the NAT entry to that different destination.

```sh
java -jar cf-nat-2.5.0.jar :5684 node1.coap.cluster:5684 node2.coap.cluster:5684 node2.coap.cluster:5784
```

Creates a (s)NAT listening on any network interfaces at UDP port 5684 (default coaps) and forwards the traffic to 3 dtls-receivers.

The application waits on the console input. If a empty newline is read, then the information with the current states is printed.

```sh
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
