# Californium - Extended Plugtest Server

Californium contains a plugtest server, that implements the test specification for the ETSI IoT, CoAP Plugtests, London, UK, 7--9 Mar 2014.

That plugtest server is extended by this example-module with

- benchmarks
- receive test
- built-in support for DTLS connection ID cluster using basic udp-load-balancers

The additional functions are available at ports 5783 and 5784 instead of the standard ports 5683 and 5684.

## General Usage

Start the server with:

```sh
java -jar cf-extplugtest-server-2.5.0.jar -h

Usage: ExtendedTestServer [-h] [--[no-]benchmark] [--dtls-only] [--[no-]
                          external] [--[no-]ipv4] [--[no-]ipv6] [--[no-]
                          loopback] [--[no-]plugtest] [--[no-]tcp]
                          [--trust-all] [--client-auth=<clientAuth>]
                          [--interfaces=<interfaceNames>[,
                          <interfaceNames>...]]...
                          [--interfaces-pattern=<interfacePatterns>[,
                          <interfacePatterns>...]]... [[--[no-]
                          dtls-cluster-backward] [--[no-]dtls-cluster-mac]
                          (--k8s-dtls-cluster=<k8sCluster> |
                          [[--dtls-cluster=<dtlsClusterNodes>[,
                          <dtlsClusterNodes>...]...]...
                          [--dtls-cluster-group=<dtlsClusterGroup>[,
                          <dtlsClusterGroup>...]]...
                          [--dtls-cluster-group-security=<dtlsClusterGroupSecuri
                          ty>]])]
      --[no-]benchmark   enable benchmark resource.
      --client-auth=<clientAuth>
                         client authentication. Values NONE, WANTED, NEEDED,
                           default NEEDED.
      --dtls-cluster=<dtlsClusterNodes>[,<dtlsClusterNodes>...]...
                         configure DTLS-cluster-node. <dtls-interface>;
                           <mgmt-interface>;<node-id>. use --- as
                           <dtls-interface>, for other cluster-nodes.
      --dtls-cluster-group=<dtlsClusterGroup>[,<dtlsClusterGroup>...]
                         enable dynamic DTLS-cluster mode. List of
                           <mgmt-interface1>,<mgmt-interface2>, ...
      --dtls-cluster-group-security=<dtlsClusterGroupSecurity>
                         enable security for dynamic DTLS-cluster. Preshared
                           secret for mgmt-interface.
      --[no-]dtls-cluster-mac
                         use MAC for cluster traffic to protect original
                           received address.
      --dtls-only        only dtls endpoints.
  -h, --help             display a help message
      --interfaces=<interfaceNames>[,<interfaceNames>...]
                         interfaces for endpoints.
      --interfaces-pattern=<interfacePatterns>[,<interfacePatterns>...]
                         interface patterns for endpoints.
      --k8s-dtls-cluster=<k8sCluster>
                         enable k8s DTLS-cluster mode. <dtls-interface>;
                           <mgmt-interface>;external-mgmt-port
      --[no-]dtls-cluster-backward
                         send messages backwards to the original receiving
                           connector.
      --[no-]external    enable endpoints on external network.
      --[no-]ipv4        enable endpoints for ipv4.
      --[no-]ipv6        enable endpoints for ipv6.
      --[no-]loopback    enable endpoints on loopback network.
      --[no-]plugtest    enable plugtest server.
      --[no-]tcp         enable endpoints for tcp.
      --trust-all        trust all valid certificates.
```

To see the set of options and arguments.

## Benchmarks

Requires to start the server with 

```sh
java -Xmx6g -XX:+UseG1GC -jar cf-extplugtest-server-2.5.0.jar --benchmark --no-plugtest
```

The performance with enabled deduplication for CON requests depends a lot on heap management. Especially, if the performance goes down after a while, that is frequently caused by an exhausted  heap. Therefore using explicit heap-options is recommended. Use the benchmark client from "cf-extplugtest-client", normally started with the shell script "benchmark.sh" there.

```sh
Benchmark clients, first request successful.
Benchmark clients created. 751 ms, 2662 clients/s
Benchmark started.
210767 requests (21077 reqs/s, 2698 retransmissions (1,28%), 0 transmission errors (0,00%), 2000 clients)
465086 requests (25432 reqs/s, 3992 retransmissions (1,57%), 0 transmission errors (0,00%), 2000 clients)
708014 requests (24293 reqs/s, 4089 retransmissions (1,68%), 0 transmission errors (0,00%), 2000 clients)
952650 requests (24464 reqs/s, 4176 retransmissions (1,71%), 0 transmission errors (0,00%), 2000 clients)
1175163 requests (22251 reqs/s, 4057 retransmissions (1,82%), 0 transmission errors (0,00%), 2000 clients)
1400495 requests (22533 reqs/s, 4188 retransmissions (1,86%), 0 transmission errors (0,00%), 2000 clients)
1635528 requests (23503 reqs/s, 3881 retransmissions (1,65%), 0 transmission errors (0,00%), 2000 clients)
1863026 requests (22750 reqs/s, 4083 retransmissions (1,79%), 0 transmission errors (0,00%), 2000 clients)
2084672 requests (22165 reqs/s, 4022 retransmissions (1,81%), 0 transmission errors (0,00%), 2000 clients)
2324696 requests (24002 reqs/s, 4126 retransmissions (1,72%), 0 transmission errors (0,00%), 2000 clients)
2542173 requests (21748 reqs/s, 4017 retransmissions (1,85%), 0 transmission errors (0,00%), 2000 clients)
2765909 requests (22374 reqs/s, 3363 retransmissions (1,50%), 0 transmission errors (0,00%), 2000 clients)
2994846 requests (22894 reqs/s, 4105 retransmissions (1,79%), 0 transmission errors (0,00%), 2000 clients)
```

(Server Intel Pentium Silver J5005 , 16 GB RAM, Ubuntu 18.04)

## Receive Test

A service, which uses requests with a device UUID to record these requests along with the source-ip and report them in a response. A client then analyze, if requests or responses may get lost. Used for long term communication tests. An example client is contained in "cf-extplugtest-client".

```sh
java -jar target/cf-extplugtest-client-2.5.0.jar ReceivetestClient --cbor -v

Response: Payload: 491 bytes
RTT: 1107ms

Server's system start: 10:49:30 25.09.2020
Request: 13:25:17 09.10.2020, received: 79 ms
    (88.65.148.189:44876)
Request: 13:25:02 09.10.2020, received: 82 ms
    (88.65.148.189:44719)
Request: 13:17:33 09.10.2020, received: 77 ms
    (88.65.148.189:39082)
Request: 13:16:52 09.10.2020, received: 75 ms
    (88.65.148.189:49398)
Request: 13:16:45 09.10.2020, received: 217 ms
    (88.65.148.189:58456)
Request: 13:06:28 09.10.2020, received: 75 ms
    (88.65.148.189:49915)
Request: 13:06:19 09.10.2020, received: 207 ms
    (88.65.148.189:45148)
Request: 13:01:04 09.10.2020, received: 76 ms
    (88.65.148.189:37379)
Request: 12:59:21 09.10.2020, received: 79 ms
    (88.65.148.189:35699)
```

## Built-in DTLS Connection ID Load-Balancer-Cluster

## Built-in Support for DTLS Connection ID Cluster using basic UDP-Load-Balancers

Currently several ideas about building a cluster using udp-load-balancer or DNS exists.

-  [Leshan Server in a cluster](https://github.com/eclipse/leshan/wiki/Using-Leshan-server-in-a-cluster) general analysis of CoAP/DTLS cluster using udp-load-balancers
-  [LVS](http://www.linuxvirtualserver.org/) cluster using an udp-load-balancer, based on temporary mapped source addresses to cluster-nodes.
-  [AirVantage / sbulb](https://github.com/AirVantage/sbulb) cluster using an udp-load-balancer, based on long-term mapped source addresses to cluster-nodes.
-  [DNS round-robin](https://en.wikipedia.org/wiki/Round-robin_DNS) cluster using DNS round-robin based load-balancer, clients only use DNS on connect and fail-over, but stick to a received IP-address for application traffic.
-  [DTLS 1.2 connection ID based load-balancer](https://github.com/eclipse/californium/wiki/DTLS-1.2-connection-ID-based-load-balancer) cluster using an udp-load-balancer, based on DTLS Connection ID mapping to cluster-nodes.

Currently no idea above will be able to provide high-availability for single messages. These solutions provide high-availability only by fail-over with a new handshake. A future improvement maybe to support a graceful shutdown and restart, so that on planed software updates no fail-over will be required.

If DTLS without Connection ID is used, the cluster depends on the udp-load-balancer to map the source-address to the desired cluster-node. If that mapping expires, frequently new DTLS handshakes are required. That is also true, if for other reasons the source-address has changed, e.g. caused by other NATs on the ip-route. That mostly results in "automatic-handshakes", with a quiet time close to the expected NAT timeout (e.g. 30s). With that, the first of the above approaches are easy, but the required handshakes will lower the efficiency. The [AirVantage / sbulb](https://github.com/AirVantage/sbulb) `long-term` mapping approach is therefore remarkable. At least, if that is the only address-changing component, it overcomes the most issues. If more address-changers are on the route, then again only new handshakes helps.

That shows a parallel to the general issue of DTLS, that changing source-addresses usually cause troubles, because the crypto-context is identified by that. [DRAFT IETF TLS-DTLS Connection ID](https://www.ietf.org/archive/id/draft-ietf-tls-dtls-connection-id-07.txt) solves that by replacing the address with a connection ID (CID). The last of the above links points to a first experiment, which requires a special setup for a ip-tables based udp-load-balancer. Now, the `extended-plugtest-server` comes with such CID based udp-load-balancer-support already built-in! With that, you may now use a basic udp-load-balancer and together with this built-in support you get a working solution! The functional principle is the same: the CID is not only used to identify the crypto-context, it is also used to identify the node of the cluster.

```sh
ID 01ab2345cd 
ID 02efd16790 
   ^^
   ||
   Node ID
```

A simple mapping would associate the first with the cluster node `01` and the second with node `02`. With that, a `DTLSConnector` is able to distinguish between dtls-cid-records for itself, and for other cluster-nodes. If a foreign dtls-cid-record is received, that dtls-cid-record is forwarded to the associated cluster-node's `DTLSConnector`. Unfortunately, forwarding messages on the java-application-layer comes with the downside, that all source-addresses are replaced. In order to keep them, the built-in-cluster uses a simple cluster-management-protocol. That prepends a new cluster-management-header, containing a type, the ip-address-length, the source-port, and the ip-address to the original dtls-cid-record.

```sh
    +-----------------------------------+
    | Type:      in/out      (1 byte )  |
    | IP-Length: n           (1 byte )  |
    | Port:      port        (2 bytes)  |
    | IP:        addr        (n bytes)  |
    | (MAC:      mac         (8 bytes)) | *
    +-----------------------------------+
    | (original dtls-cid-record)        |
    | content-type: tls12_cid (1 byte)  |
    | ProtocolVersion: 1.2    (2 bytes) |
    | ...                               |
    +-----------------------------------+
```

> (* optional, if encryption is enabled for cluster-management)

The receiving `DTLSConnector` (node 2) is then decoding that cluster-management-record and start to process it, as it would have been received by itself. If outgoing response-messages are to be sent by this `DTLSConnector` (node 2), the message is prepended again by that cluster-management-header and send back to the original receiving `DTLSConnector` (node 1, as "router"). That finally forwards the dtls-record to the addressed peer.

To easier separate the traffic, cluster-management-traffic uses a different UDP port.

```
    +--------+  +---+  +------------+     +----------------------------+
    | peer 1 |  | L |  | IPa => IPb |     | DTLS Connector, IPb        |
    | IPa    | ======= +------------+ ==> | node 1, mgmt-intf IP1      |
    +--------+  | O |  | CID 02abcd |     +----------------------------+
    |        |  | A |  +------------+     |                            |
    |        |  | D |                     |                            |
    |        |  | | |  +------------+     |                            |
    |        |  | B |  | IPb => IPa |     |                            |
    |        | <====== +------------+ === |                            |
    |        |  | A |  | ???        |     |                            |
    +--------+  | L |  +------------+     +----------------------------+
                | A |                           ||              /\
                | N |                           ||              ||
                | C |                     +------------+  +------------+
                | E |                     | IP1 => IP2 |  | IP2 => IP1 |
                | R |                     +------------+  +------------+
                +---+                     | IN,IPa     |  | OUT,IPa    |
                                          | CID 02abcd |  | ???        |
                                          +------------+  +------------+
                                                ||              ||
                                                \/              ||
                                          +----------------------------+
                                          | DTLS Connector, IPc        |
                                          | node 2, mgmt-intf IP2      |
                                          +----------------------------+
                                          | CID 02abcd: (keys)         |
                                          |                            |
                                          |                            |
                                          +----------------------------+
```

If a basic udp-load-balancer chose the "wrong DTLS Connector", the cluster internal message forwarding based on the CID corrects that and forwards the message to the "right DTLS Connector".

### Built-in Cluster Modes

The current build-in cluster comes with three modes:

-  static, the nodes are statically assigned to CIDs.
-  dynamic, the nodes are dynamically assigned to CIDs
-  k8s, the nodes are discovered using the k8s API and dynamically assigned to CIDs 

### Static Nodes

Start node 1 on port 15784, using `localhost:15884` as own cluster-management-interface. Provide `localhost:25884` as static cluster-management-interface for node 2:

```sh
java -jar target/cf-extplugtest-server-2.5.0.jar --dtls-cluster ":15784;localhost:15884;1,---;localhost:25884;2"
```

Start node 2 on port 25784, using `localhost:25884` as own cluster-management-interface. Provide `localhost:15884` as static cluster-management-interface for node 1:

```sh
java -jar target/cf-extplugtest-server-2.5.0.jar --dtls-cluster "---;localhost:15884;1,:25784;localhost:25884;2"
```

In that mode, the `address:cid` pairs of the other/foreign nodes are static.

To use that setup, a basic udp-load-balancer may be used in front. The [Cf-NAT](https://github.com/eclipse/californium/tree/master/cf-utils/cf-nat) offers such a function:

```sh
java -jar cf-nat-2.5.0.jar :5784 <host>:15784 <host>:25784
```

Replace `<host>` by the host the `cf-extplugtest-server` has been started.

### Dynamic Nodes

Start node 1 on port 15784, using `localhost:15884` as own cluster-management-interface. Provide `localhost:25884,localhost:35884` as cluster-management-interfaces for the other nodes of this cluster group:

```sh
java -jar target/cf-extplugtest-server-2.5.0.jar --dtls-cluster ":15784;localhost:15884;1" --dtls-cluster-group="localhost:25884,localhost:35884"
```

Start node 2 on port 25784, using `localhost:25884` as own cluster-management-interface. Provide `localhost:15884,localhost:35884` as cluster-management-interfaces for the other nodes of this cluster group:

```sh
java -jar target/cf-extplugtest-server-2.5.0.jar --dtls-cluster ":25784;localhost:25884;2" --dtls-cluster-group="localhost:15884,localhost:35884"
```

Start node 3 on port 35784, using `localhost:35884` as own cluster-management-interface. Provide `localhost:15884,localhost:25884` as cluster-management-interfaces for the other nodes of this cluster group:

```sh
java -jar target/cf-extplugtest-server-2.5.0.jar --dtls-cluster ":35784;localhost:35884;3" --dtls-cluster-group="localhost:15884,localhost:25884"
```

In that mode, the `address:cid` pairs of the other/foreign nodes are dynamically created using additional messages of the cluster-management-protocol.

```sh
    +-----------------------------------+
    | Type:      ping/pong   (1 byte )  |
    | Node-ID:   id          (4 bytes ) | 
    +-----------------------------------+
```

This cluster internal management traffic could be optionally encrypted using DTLS with PSK (all nodes share the same identity and secret).

```sh
java -jar target/cf-extplugtest-server-2.5.0.jar --dtls-cluster ":25784;localhost:25884;2" --dtls-cluster-group="localhost:15884,localhost:35884 --dtls-cluster-group-security=topSecret!"
```

To use that setup, a basic udp-load-balancer may be used in front as for the mode before. Just add the new third destination.

```sh
java -jar cf-nat-2.5.0.jar :5784 <host>:15784 <host>:25784 <host>:35784
```

### k8s Nodes

Start nodes in a container using port `5784`, and `<any>:5884` as own cluster-management-interface. Additionally provide the external port of the cluster-management-interface also with `5884`.

```sh
CMD ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75", "-jar", "/opt/app/cf-extplugtest-server-2.5.0.jar", "--no-plugtest", "--no-tcp", "--benchmark", "--k8s-dtls-cluster", ":5784;:5884;5884"]
```

Example `CMD` statement for docker (":5884" for "<any>:5884", "5884" for just port 5884, see [Dockerfile](service/Dockerfile)).

To use this container with k8s, a "statefulSet" is required (see [k8s.yaml](service/k8s.yaml) for "StatefulSet" and "Service" description). Some configuration values are passed in using the "secret" "cf-extserver-config".
To deploy this into a local microk8s instance, the script [deploy_microk8s.sh](service/deploy_microk8s.sh) contains the statements to build the container, to push it to the local repository, create the "secret" and then apply the k8s description into the k8s namespace "cali".

In that k8s mode, the cluster-nodes group is requested from the k8s management APIs for pods.
The pods in the example are marked with 

```
"metadata: labels: app: cf-extserver"
```

so a 

```
GET /api/v1/namespaces/<namespace>/pods/?labelSelector=app%3Dcf-extserver
```

can be used to select the right pod-set for this cid-cluster.

In that mode, the `address:cid` pairs of the other/foreign nodes of the pods-set are dynamically created using the same additional messages of the cluster-management-protocol, then in `Dynamic Nodes` above.

To enable the the encryption for the cluster internal management traffic, the `secret`s 

- dtls_cid_mgmt_identity="cid-cluster-manager"
- dtls_cid_mgmt_secret_base64="c1BKR285VGdpTlJ2ak1UYg=="

are used.

Using a k8s "StatefulSet" comes with a "in-cluster load balancing" based on the k8s kube-proxy mode. For test just use the exposed node-port on `30784`. If address changes should be considered, the `cf-nat` ahead may simulate such address changes. Read the next sections for more details about that.

### Test the dtls-cid-cluster

To test the dtls-cid-cluster a coap-client can be used. For the k8s approach, start it with

```sh
java -jar cf-client-2.5.0.jar --method GET coaps://<host>:30784/context

==[ CoAP Request ]=============================================
MID    : 12635
Token  : E042D951531E7FDB
Type   : CON
Method : 0.01 - GET
Options: {"Uri-Host":"<host>", "Uri-Path":"context"}
Payload: 0 Bytes
===============================================================

>>> DTLS(<host>:30784,ID:3559881395)
>>> TLS_PSK_WITH_AES_128_CCM_8
>>> PreSharedKey Identity [identity: cali.30FC0A725D79F82C]

Time elapsed (ms): 580
==[ CoAP Response ]============================================
MID    : 12635
Token  : E042D951531E7FDB
Type   : ACK
Status : 2.05 - CONTENT
Options: {"Content-Format":"text/plain"}
RTT    : 580 ms
Payload: 172 Bytes
---------------------------------------------------------------
ip: ???.???.???.???
port: 40163
node-id: 2
peer: cali.30FC0A725D79F82C
cipher-suite: TLS_PSK_WITH_AES_128_CCM_8
read-cid: 02F9CF39DE39
write-cid: 
server: Cf 2.5.0-SNAPSHOT
===============================================================
```

This assumes, that the k8s "cf-extserver-service" is of type `NodePort`.

If you execute the client multiple times, you will see different `node-id`s, when the requests are processed by different nodes.

Note: if the line with `read-cid` is missing, the DTLS Connection ID support is not enabled. Check, if `DTLS_CONNECTION_ID_LENGTH` is set in "Californium.properties" to a number. Even `0` will enable it. But an empty value disables the DTLS Connection ID support!

For the other two variants above, `Static Nodes` or `Dynamic Nodes`, the `cf-nat` may be used as load-balancer. In that cases, just use the address of the `cf-nat` as destination, e.g.

```sh
java -jar cf-client-2.5.0.jar --method GET coaps://<nat>:5784/context
```

### Test the dtls-cid-cluster with Cf-NAT 

To test, that the dtls-cid-cluster even works, if the client's address is changed, such a address change can be simulated using [Cf-NAT](https://github.com/eclipse/californium/tree/master/cf-utils/cf-nat)

```sh
java -jar cf-nat-2.5.0.jar :5784 <host>:30784
```

Starts a NAT at port `5784`, forwarding the traffic to `<host>:30784`.
Type `help` on the console of the NAT and press `<enter>` in that console.

```sh
help - print this help
info or <empty line> - list number of NAT entries and destinations
exit or quit - stop and exit
clear [n] - drop all NAT entries, or drop n NAT entries
reassign - reassign incoming addresses
rebalance - reassign outgoing addresses
add <host:port> - add new destination to load balancer
remove <host:port> - remove destination from load balancer
reverse (on|off) - enable/disable reverse address updates.
```

Start two [cf-browser-2.5.0](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-browser/2.5.0/cf-browser-2.5.0.jar) instances. Enter as destination `coaps://<nat-host>:5784/context` and execute a `GET` in both clients. Do they show different `node-ids`? If not, restart one as long as you get two different `node-id`s. Also check, if the line with `read-cid` is missing. If so, the DTLS Connection ID support is not enabled. Check, if `DTLS_CONNECTION_ID_LENGTH` is set in "Californium.properties" to a number. Even `0` will enable it. But a empty value disables the DTLS Connection ID support!

```sh
ip: ?.?.?.?
port: 59957
node-id: 2
peer: Client_identity
cipher-suite: TLS_PSK_WITH_AES_128_CCM_8
read-cid: 023F2640E574
write-cid: 
server: Cf 2.5.0-SNAPSHOT
```

Now, press `<enter>` on the console of the NAT.

```sh
2 NAT entries, reverse address update disabled.
1 destinations.
Destination: <host>:30784, usage: 2
```

You get a summary of the entries in the NAT.
Enter `clear` on the console of the NAT and press `<enter>` in that console.

```sh
2 - NAT entries dropped.
```

Now execute the GET again. You should still get the same `node-id`s on the same `cf-browser`, with different `port`s, because the messages are mapped to new NAT entries.

```sh
ip: ?.?.?.?
port: 41083
node-id: 2
peer: Client_identity
cipher-suite: TLS_PSK_WITH_AES_128_CCM_8
read-cid: 023F2640E574
write-cid: 
server: Cf 2.5.0
```

You may retry that, you should see the same ip-address/port (5-tuple), if you retry it within the NATs timeout (30s).
Now, either chose to `clear` the NAT again, or 

**... coffee break ...** (at least 30s)

Retry it, you get now different ports.

```sh
ip: ?.?.?.?
port: 27016
node-id: 2
peer: Client_identity
cipher-suite: TLS_PSK_WITH_AES_128_CCM_8
read-cid: 023F2640E574
write-cid: 
server: Cf 2.5.0
```

You may even restart the NAT, the coaps communication will still work.

### Test the dtls-cid-cluster, NAT, and Benchmark 

You may use the benchmark of cf-extplugtest-client together with the NAT and the dtls-cid-cluster to see the performance penalty of the additional record forwarding with the cluster-management-protocol.

Open a console in that sub-module. Configure benchmark to use only coaps in that console.

```sh
>$ export USE_TCP=0
>$ export USE_UDP=1
>$ export USE_PLAIN=0
>$ export USE_SECURE=1
```

Execute benchmark from that console

```sh
./benchmark.sh <nat-host>
```

```sh
77826 requests (7783 reqs/s, 419 retransmissions (0,54%), 0 transmission errors (0,00%), 2000 clients)
300368 requests (22254 reqs/s, 4557 retransmissions (2,05%), 0 transmission errors (0,00%), 2000 clients)
573903 requests (27354 reqs/s, 6584 retransmissions (2,41%), 0 transmission errors (0,00%), 2000 clients)
849782 requests (27588 reqs/s, 6366 retransmissions (2,31%), 0 transmission errors (0,00%), 2000 clients)
1125439 requests (27566 reqs/s, 6393 retransmissions (2,32%), 0 transmission errors (0,00%), 2000 clients)
1402258 requests (27682 reqs/s, 6517 retransmissions (2,35%), 0 transmission errors (0,00%), 2000 clients)
1683178 requests (28092 reqs/s, 6439 retransmissions (2,29%), 0 transmission errors (0,00%), 2000 clients)
1965758 requests (28258 reqs/s, 6422 retransmissions (2,27%), 0 transmission errors (0,00%), 2000 clients)
2252115 requests (28636 reqs/s, 6592 retransmissions (2,30%), 0 transmission errors (0,00%), 2000 clients)
2444728 requests (19261 reqs/s, 5354 retransmissions (2,78%), 0 transmission errors (0,00%), 2000 clients)
2669267 requests (22454 reqs/s, 5711 retransmissions (2,54%), 0 transmission errors (0,00%), 2000 clients)
2890107 requests (22084 reqs/s, 5481 retransmissions (2,48%), 0 transmission errors (0,00%), 2000 clients)
```

(Server Intel Pentium Silver J5005 , 16 GB RAM, Ubuntu 18.04)

That benchmark shows a penalty of a little more than 20% (22000 to 28000).

You may use k8s to see the CPU usage of the pods.

```sh
kubectl -n cali top pod
NAME             CPU(cores)   MEMORY(bytes)
cf-extserver-0   1108m        334Mi
cf-extserver-1   1070m        341Mi
cf-extserver-2   1054m        321Mi
```


You may also restart pods using k8s,

```sh
kubectl -n cali delete pod/cf-extserver-1
```

Remember high-availability is not about single requests, it's about fail-over with a new handshake.

```sh
16:28:53.470: client-364: Error after 3278 requests. timeout
16:28:53.668: client-288: Error after 5489 requests. timeout
16:28:53.792: client-779: Error after 4536 requests. timeout
16:28:53.947: client-687: Error after 5195 requests. timeout
16:28:53.951: client-803: Error after 3198 requests. timeout
16:28:54.201: client-477: Error after 3187 requests. timeout
16:28:54.319: client-1279: Error after 4522 requests. timeout
9458438 requests (25208 reqs/s, 6078 retransmissions (2,41%), 48 transmission errors (0,02%), 2000 clients)
9711707 requests (25327 reqs/s, 6020 retransmissions (2,38%), 0 transmission errors (0,00%), 2000 clients)
```

That result in many clients reach their timeout and restart their communication with a new handshake.

```sh
kubectl -n cali top pod
NAME             CPU(cores)   MEMORY(bytes) 
cf-extserver-0   860m         331Mi
cf-extserver-1   577m         218Mi
cf-extserver-2   1190m        322Mi
```

The cluster is quite out of balance. With more new handshakes, it gets balanced again.

## Preview Of Future Improvements

As mentioned above, in my setup the overhead of forwarding and backwarding the records is about 20%.
An idea to improve that, is not to backward the records and instead send them direct. That doesn't work out of the box, because the involved "sNAT" (e.g. kube-proxy) doesn't send a record out of its path.

```
    +--------+  +---+  +------------+     +--------------------------+
    | peer 1 |  |   |  | IPa => IPb |     | DTLS Connector, IPb      |
    | IPa    | ======= +------------+ ==> | node 1, mgmt-intf IP1    |
    +--------+  |   |  | CID 02abcd |     +--------------------------+
    |        |  |   |  +------------+     |                          |
    |        |  | L |                     |                          |
    |        |  | O |                     +--------------------------+
    |        |  | A |                           ||
    |        |  | D |                           ||
    |        |  | | |                     +------------+
    |        |  | B |                     | IP1 => IP2 |
    |        |  | A |                     +------------+
    |        |  | L |                     | IN,IPa     |
    |        |  | A |                     | CID 02abcd |
    |        |  | N |                     +------------+
    |        |  | C |                           ||
    |        |  | E |                           \/
    |        |  | R |                     +--------------------------+
    |        |  |   |  +------------+     | DTLS Connector, IPc      |
    |        |  |   |  | IPc => IPa |     | node 2, mgmt-intf IP2    |
    |        | <====== +------------+ === +--------------------------+
    |        |  |   |  | ???        |     | CID 02abcd: (keys)       |
    |        |  |   |  +------------+     |                          |
    +--------+  +---+                     +--------------------------+
```

The communication is routed through NATs/LoadBalancer. A entry for `IPa => IPb` can usually not be used to send a record back from `IPc`. The simple load-balancer `cf-nat` offers therefore the "reverse address update feature". With that, sending back a message with `IPc => IPa` is not only possible, it updates the load-balancer destination to the right `IPc` node for this client's traffic. This works for the first two setups `Static Notes` and `Dynamic Notes`, if the `cf-nat`is used as load-balancer and started with

```sh
java -jar cf-nat-2.5.0.jar :5784 <host>:15784 <host>:25784 -r
```

To check, if reverse address update is enabled, press `<enter>` on the console of the NAT.

```sh
0 NAT entries, reverse address update enabled.
2 destinations.
Destination: <host>:15784, usage: 0
Destination: <host>:25784, usage: 0
```

When starting the nodes, add `--no-dtls-cluster-backward`.

Node 1

```sh
java -jar target/cf-extplugtest-server-2.5.0.jar --dtls-cluster ":15784;localhost:15884;1" --dtls-cluster-group="localhost:25884" --no-dtls-cluster-backward
```
Node 2

```sh
java -jar target/cf-extplugtest-server-2.5.0.jar --dtls-cluster ":25784;2ocalhost:15884;2" --dtls-cluster-group="localhost:15884" --no-dtls-cluster-backward
```

You may try out the benchmark above and `clear` the NAT during execution. The 20% penalty is gone! The cluster adjusts very fast the load-balancers NAT entries with the right address.

So, let's check, if load-balancer are found, which could be used for that scenario.
Maybe [AirVantage / sbulb](https://github.com/AirVantage/sbulb) offers such a option in the future.
