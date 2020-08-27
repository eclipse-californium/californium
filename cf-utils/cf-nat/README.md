# NAT / LoadBalancer Simulator

In order to test NAT and LoadBalancer specific situations, this module contains a simple simulator implementation for a NAT and/or load-balancer. It offers an API for own test-implementations, and two example applications.

Usage:

```shell
java -jar cf-nat-<version>.jar [localinterface]:port destination:port [destination2:port2 ...] [-d<messageDropping%>|[-f<messageDropping%>][-b<messageDropping%>]] [-s<sizeLimit>]
```

The NAT receives UDP messages on the local interface and port, creates outgoing sockets for each source endpoint of the received messages, and forwards the message using the new outgoing socket (source-NAT). If the outgoing socket receives a message back, that is the "backwarded" using the local-interface and port.

If more than one destination is given, the load-balancer is activated.
The load-balancer receives UDP messages on the local interface and port, creates outgoing sockets for each source endpoint of the received messages and selects a destination randomly from the provided ones, and forwards the message using the new outgoing socket (source-NAT). If the outgoing socket receives a message back, that is the "backwarded" using the local-interface and port.

The application waits on the console input. If a newline is read, the NAT mode reassigns new outgoing sockets for the entries, while the load-balancer mode reassigns new randomly selected destination to the entries. Additionally to the empty input, these commands are supported:

- help - print this help
- reassign - reassign mapped addresses for outgoing traffic
- rebalance - reassign destinations for outgoing traffic randomly
- add ``<host:port>`` - add new destination to load-balancer, e.g. "add node1.coaps.cluster:5684"
- remove ``<host:port>`` - remove destination from load-balancer
