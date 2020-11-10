# Californium (Cf) - DTLS Cluster Support

[Californium/Scandium](https://github.com/eclipse/californium/tree/master/scandium-core) offers starting with the 2.5.0 the feature to forward tls_cid records to the `DTLSConnector`, which has the security context (e.g. keys) for that.

To keep the function in  _Scandium_  simple, only a basic forwarding and backwarding is implemented there. This function is based on a implementation of `DtlsClusterConnector.ClusterNodesProvider`. This cluster support module extends that basic function, by

- dynamically managing nodes
- support k8s API to discover nodes

## DTLS Cluster Manager

That component runs on every cluster node. It frequently refreshes a nodes table as base for the  `DtlsClusterConnector.ClusterNodesProvider`. Therefore a simple management protocol is used:

```sh
    +-----------------------------------+
    | Type:      ping/pong   (1 byte )  |
    | Node-ID:   id          (4 bytes ) | 
    +-----------------------------------+
```

Each node sends to all other cluster nodes such a `ping` message, if no `ping` or `pong`messages is received from that for the `refresh-interval` (default 6s). Nodes, which don't response to such `ping` for `expirationTime` (default 4s), are considered to be offline and are removed from the nodes table.

Each node also uses the `DtlsClusterManager.ClusterNodesDiscover` to discover possible new nodes. That's called based on the `discover-interval` (default 30s), or when no other node is in the nodes-table or a node is removed from the table recently.

## k8s Discover Client

The `K8sManagementDiscoverJdkClient` implements `DtlsClusterManager.ClusterNodesDiscover` using the k8s REST API to discover the current Californium pods. See the javadoc there for more detials.



