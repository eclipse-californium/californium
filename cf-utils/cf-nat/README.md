# NAT / LoadBalancer Simulator

In order to test NAT and LoadBalancer specific situations, this module contains a simple simulator implementation for a NAT and/or LoadBalancer. It offers an API for own test-implementations, and two example applications.

## NAT

Usage:

```shell
java -jar cf-nat-<version>.jar NAT [localinterface]:port destination:port [<messageDropping%>|-f<messageDropping%>|-b<messageDropping%>] [-s<sizeLimit>]
```

The NAT receives UDP messages on the local interface and port, creates outgoing sockets for each source endpoint of the received messages, and forwards the message using the new outgoing socket (source-NAT). If the outgoing socket receives a message back, that is the "backwarded" using the local-interface and port.

The NAT waits on the console input. If a newline is read, the NAT reassigns new outgoing sockets
for the entries.

## LoadBalancer

Usage:

```shell
java -cp cf-nat-<version>.jar LB [localinterface]:port destination1:port1 destination2:port2 [destination3:port3 ...]
```

The LoadBalancer receives UDP messages on the local interface and port, creates outgoing sockets for each source endpoint of the received messages and selects a destination randomly from the provided ones, and forwards the message using the new outgoing socket (source-NAT). If the outgoing socket receives a message back, that is the "backwarded" using the local-interface and port.

The LoadBalancer waits on the console input. If a newline is read, the LoadBalancer reassigns new randomly selected destination to the entries.
