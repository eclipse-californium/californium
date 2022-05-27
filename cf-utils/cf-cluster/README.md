![Californium logo](../../cf_64.png)

# Californium (Cf) - k8s Support

[Californium/Scandium](https://github.com/eclipse/californium/tree/main/scandium-core) offers since 3.0 two extensions to be used with k8s.

- Built-in support for DTLS Connection ID cluster using basic UDP-load-balancers
- DTLS graceful restart (with or without that cluster support)

## Californium (Cf) - k8s Built-in Support for DTLS Connection ID Cluster

[Californium/Scandium](https://github.com/eclipse/californium/tree/main/scandium-core) offers starting with the 2.5.0 the feature to forward tls_cid records to the `DTLSConnector`, which has the security context (e.g. keys) for that.

To keep the function in  _Scandium_  simple, only a basic forwarding and backwarding is implemented there. This function is based on a implementation of `DtlsClusterConnector.ClusterNodesProvider`. This cluster support module extends that basic function, by

- dynamically managing nodes
- support k8s API to discover nodes

### DTLS Cluster Manager

That component runs on every cluster node. It frequently refreshes a nodes table as base for the  `DtlsClusterConnector.ClusterNodesProvider`. Therefore a simple management protocol is used:

```sh
    +-----------------------------------+
    | Type:      ping/pong   (1 byte )  |
    | Node-ID:   id          (4 bytes ) | 
    +-----------------------------------+
```

Each node sends to all other cluster nodes such a `ping` message, if no `ping` or `pong` messages is received from that for the `refresh-interval` (default 4s). Nodes, which don't response to such `ping` for `expirationTime` (default 6s), are considered to be offline and are removed from the nodes table.

Each node also uses the `DtlsClusterManager.ClusterNodesDiscover` to discover possible new nodes. That's called based on the `discover-interval` (default 10s), or when no other node is in the nodes-table or a node is removed from the table recently.

The `refresh`, `discover` and `expiration` is executed by a timer (default interval 2s).

## k8s API Client - Discover and Read Pod's Metadata

The `K8sDiscoverClient` implements `DtlsClusterManager.ClusterNodesDiscover` using the k8s REST API via `K8sManagementClient` to discover the current Californium pods based on labels. The client requires therefore the permission to list and get pods. If no other trusted CA certificate is provided as "https_k8s_client_trust.pem", the trust CA of the service account is used. Also, if a empty token is provided, the token of that service account is used as default.
If RBAC is activated in the k8s installation, the client requires the permissions to get and list pods. Therefore [rbac](../../demo-apps/cf-extplugtest-server/service/k8s_rbac.yaml) is applied to grant these rights to the service account.

See the javadoc there for more details.

The k8s demonstration setups comes with two variants:

- a cluster setup using a [statefulset a/b](../../demo-apps/cf-extplugtest-server/service/k8s_statefulset_a.yaml) and each pod discovers the other pods using the k8s label "controller-revision-hash".
- a single server setup using a [deployment](../../demo-apps/cf-extplugtest-server/service/k8s_deployment.yaml) supporting only 1 replica. The other pod is discovered using the k8s label "app".

Note: In both variants, the defining yaml doesn't contain the right image. The "deploy_k8s.sh" script sets the image in a second step. That is only intended for easier testing. Usually the yaml should contain already the right image.

## k8s Blue/Green Update With DTLS Graceful Restart

Since the release 3.0, _Scandium_ offers saving and loading of DTLS states.

That enables a implementation of a blue-green update without losing the DTLS states. Client may continue to send data without new handshakes. To switch between blue/green takes a small couple of seconds. The client, which sends data in that switching-period, will therefore lose their messages or they will need to resend them. Therefore `CON` messages are very well for this case. DTLS handshakes with the switching period will fail, the clients are required to retry the handshake later.

To implement a blue/green update with k8s, following k8s demonstration setup is used:

Cluster:
- [service](../../demo-apps/cf-extplugtest-server/service/k8s.yaml)
- [rbac](../../demo-apps/cf-extplugtest-server/service/k8s_rbac.yaml)
- [statefulset a](../../demo-apps/cf-extplugtest-server/service/k8s_statefulset_a.yaml)
- [statefulset b](../../demo-apps/cf-extplugtest-server/service/k8s_statefulset_b.yaml) same as `a`, but with different name.

Or as single server alternative to the `statefulset`s. 
- [deployment](../../demo-apps/cf-extplugtest-server/service/k8s_deployment.yaml)

The `service` selects all "ready" pods by the label "app: cf-extserver", which is the same for `a` and `b`. Therefore it is essential, that the pods of each statefulset reports "ready" coordinated. In order to do that, two components have been added:

- `JdkK8sMonitoringService` a http/https server:
    - check the readiness of the CoAP-server and other components.
    - offer the download of DTLS states and stops the CoAP-server on that.
- `RestoreHttpClient` a https client:
    - determines it's blue/green pod-double in the other statefulset
    - download the DTLS states from the `JdkK8sMonitoringService` of the double
    - restores the DTLS states from the downloaded data and reports `ready`.

The update process of the statefulset uses the following steps:
- check, if all current pods are ready before starting the update.
- label all current pods to be updated ("restore=true"). That prevents accidentally reverse restore by a restart of the old pods during the update.
- create new pods using a new statefulset with different name (a/b)
- the new pods starts the dtls-cid-cluster and waits, until that is ready.
- then the new pods use the `RestoreHttpClient` to download and restore the DTLS states from the corresponding old pod.
- The `JdkK8sMonitoringService` on the old pods stops the coap-server on the download and with that stops to reports "ready". That stops also the headless service to forward messages to this old pod.
- the new pods starts to report "ready", when they finished to restore the downloaded dtls states. That also starts the headless service to forward messages to the new pod.
- when all new pods are "ready", then the old statefulset is deleted.

For the single server setup, it's simpler:
- check, if the current pod is ready before starting the update.
- label the current pod to be updated ("restore=true"). That prevents accidentally reverse restore by a restart of the old pod during the update.
- create new pod updating the deployment with the new image
- the new pod starts and uses the `RestoreHttpClient` to download and restore the DTLS state from the corresponding old pod.
- The `JdkK8sMonitoringService` on the old pod stops the coap-server on the download and with that stops to reports "ready". That stops also the headless service to forward messages to this old pod.
- the new pod starts to report "ready", when it finished to restore the downloaded dtls state. That also starts the headless service to forward messages to the new pod.

The `cf-extplugtest-server` contains a [script](../../demo-apps/cf-extplugtest-server/service/deploy_k8s.sh) for that approach.

```sh
service/deploy_k8s.sh update0

... docker ...

a reports ready, start update b
pod/cf-extserver-a-1 labeled
pod/cf-extserver-a-2 labeled
pod/cf-extserver-a-0 labeled
statefulset.apps/cf-extserver-b created
statefulset.apps/cf-extserver-b patched
 0 secs. a reports 3, b reports 0 of 0 ready.
 2 secs. a reports 3, b reports 0 of 3 ready.
 5 secs. a reports 3, b reports 0 of 3 ready.
 7 secs. a reports 3, b reports 0 of 3 ready.
 10 secs. a reports 3, b reports 0 of 3 ready.
 12 secs. a reports 3, b reports 0 of 3 ready.
 15 secs. a reports 2, b reports 3 of 3 ready.
 17 secs. a reports 0, b reports 3 of 3 ready.
statefulset.apps "cf-extserver-a" deleted
 18 secs. b updated. <date and time>
```

Output of Benchmark client during the update:

```sh
150016 requests (5311 reqs/s, 19 retransmissions (0,04%), 0 transmission errors (0,00%), 4000 clients)
199488 requests (4947 reqs/s, 565 retransmissions (1,12%), 0 transmission errors (0,00%), 4000 clients)
249253 requests (4977 reqs/s, 1412 retransmissions (2,88%), 0 transmission errors (0,00%), 4000 clients)
302522 requests (5327 reqs/s, 0 retransmissions (0,00%), 0 transmission errors (0,00%), 4000 clients)
348184 requests (4566 reqs/s, 1846 retransmissions (4,00%), 0 transmission errors (0,00%), 4000 clients)
387300 requests (3912 reqs/s, 1198 retransmissions (2,81%), 0 transmission errors (0,00%), 4000 clients)
408632 requests (2133 reqs/s, 7193 retransmissions (39,47%), 0 transmission errors (0,00%), 4000 clients)
457718 requests (4909 reqs/s, 1175 retransmissions (2,43%), 0 transmission errors (0,00%), 4000 clients)
510132 requests (5241 reqs/s, 250 retransmissions (0,48%), 0 transmission errors (0,00%), 4000 clients)
562743 requests (5261 reqs/s, 83 retransmissions (0,16%), 0 transmission errors (0,00%), 4000 clients)
606353 requests (4361 reqs/s, 2552 retransmissions (5,85%), 0 transmission errors (0,00%), 4000 clients)
659285 requests (5293 reqs/s, 36 retransmissions (0,07%), 0 transmission errors (0,00%), 4000 clients)
704071 requests (4479 reqs/s, 1828 retransmissions (3,98%), 0 transmission errors (0,00%), 4000 clients)
754428 requests (5036 reqs/s, 1101 retransmissions (2,24%), 0 transmission errors (0,00%), 4000 clients)
803779 requests (4935 reqs/s, 1004 retransmissions (2,03%), 0 transmission errors (0,00%), 4000 clients)
849525 requests (4575 reqs/s, 1908 retransmissions (4,16%), 0 transmission errors (0,00%), 4000 clients)
898777 requests (4925 reqs/s, 328 retransmissions (0,66%), 0 transmission errors (0,00%), 4000 clients
```

During the switch between blue and green, a increasing number of retransmissions occurs (here 39,47%).

**Note:**
> switching the UDP traffic between blue and green sometimes fails for a couple of clients. The service mapping of these clients seems to stick to the old pods. Using the [iptables proxy mode](https://kubernetes.io/docs/concepts/services-networking/service/#proxy-mode-iptables) that seems to depend on the UDP connection timeout. On Ubuntu 18.04 these timeouts are defined by:

```sh
/proc/sys/net/netfilter/nf_conntrack_udp_timeout
/proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream 
```

> The values are read with:

```sh
cat /proc/sys/net/netfilter/nf_conntrack_udp_timeout
30
cat /proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream 
120
```

> The current default values are 30s and 120s. It may be possible to adjust these values in order to reduce the stickiness. Or to use an other implementation for the service proxy with different times. For clients it is therefore important, to reach that time with the CON-retransmission-timeout. If the default values for these timeouts are not adapted, a larger ON-retransmission-timeout can be achieved by changing the value for `MAX_RETRANSMIT` in the "Californium3.properties" (or "Californium3Benchmark.properties", if the BenchmarkClient is used) from 4 to 5.

```sh
MAX_RETRANSMIT=5
```

## k8s Configuration

The k8s support is configured by environment variables.

Common:
- `KUBECTL_HOST` hostname of the k8s API. Default "kubernetes.default.svc".
- `KUBECTL_NAMESPACE` namespace for k8s components. Default read from "/var/run/secrets/kubernetes.io/serviceaccount/namespace".
- `KUBECTL_TOKEN` bearer token for k8s API. Default read from "/var/run/secrets/kubernetes.io/serviceaccount/token".

CID Cluster:
- `KUBECTL_SELECTOR` selector to get pods of cluster set. Defaults to label selector.
- `KUBECTL_SELECTOR_LABEL` label selector. Selects pods as cluster set with same values in the label. Default label "controller-revision-hash".
- `KUBECTL_NODE_ID` node-id to be used for DTLS Connection ID cluster. Default extracted from hostname.
- `DTLS_CID_MGMT_IDENTITY` PSK identity for cluster internal communication.
- `DTLS_CID_MGMT_SECRET_BASE64` PSK secret in base64 for cluster internal communication.

Single server's graceful restart:
- `KUBECTL_RESTORE_SELECTOR_LABEL` label selector to select restore double for single server. Selects pod to restore data from. Default label "app".

