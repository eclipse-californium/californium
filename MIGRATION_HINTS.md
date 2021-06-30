![Californium logo](cf_64.png)

# Californium (Cf) - Migration Hints

June, 2021

The version 2.x is now out for about more than a year and reached version 2.6.3.
We currently started to work on a 3.0 starting with removing deprecates APIs.

To migrate to the 3.0 this gives some hints to do so. If you miss something, don't hesitate to create an issue.

Please, keep in mind, that the 3.0 API is under develop.

## General

This document doesn't contain hints for migrating versions before 2.0. That excludes also hints to migrate any of the 2.0 MILESTONE releases.

If a 2.0.0 or newer is used, it's recommended to update first to 2.6.3 and cleanup all deprecation using the documentation on the deprecation.

## First Experience

Migrating [Eclipse/Hono](https://github.com/eclipse/hono) and [Eclipse/Leshan](https://github.com/eclipse/leshan) the major changes, which requires adaption, are the changes in the DTLS configuration and the related callbacks. Reading the section below should help all to overcome issues caused by these changes.

## Noteworthy Behavior Changes

### Element-Connector:

`Bytes.equals(Object other)`:

Since 3.0 the sub-class may be ignored, depending on the provided value of the `useClassInEquals` parameter in `Bytes(byte[], int, boolean, boolean)`. The default behavior is changed to ignore the sub-class.

`StringUtil.getUriHostname(InetAddress address)`:

The IPv6-scope-separator "%" is replaced by the URL-encoded form "%25" (also fixed in 2.6.4).

`DtlsEndpointContext.KEY_RESUMPTION_TIMEOUT` is renamed into `DtlsEndpointContext.KEY_AUTO_HANDSHAKE_TIMEOUT`. The key's value is adjusted as well. The feature not only supports abbreviated handshakes, it also starts full handshakes, if the session is not able to be resumed.

### Scandium:

Redesigned! May cause also unaware changes! If you detect one, please create an issue on 
[Eclipse/Californium](https://github.com/eclipse/californium/issues).

The Alert during the handshakes are adapted (more) towards the definitions in 
[RFC 5246, Section 7.2, Alert Protocol](https://tools.ietf.org/html/rfc5246#section-7.2).

During the `CLIENT_HELLO` / `SERVER_HELLO` cipher suite and parameter negotiation a
`HANDSHAKE_FAILURE` is sent, if no common cipher suite or parameter are available.
If in later messages unsupported parameters are used, a `ILLEGAL_PARAMETER` is sent.
For unexpected certificate types a `UNSUPPORTED_CERTIFICATE` is sent.
If certificate verification fails, a `DECRYPT_ERROR` is sent.

[RFC 7627, Extended Master Secret](https://tools.ietf.org/html/rfc7627) TLS extension is introduced and enabled by default. If this extension is not used, the session is not resumable (until the configuration is adapted to none or optional).

The encoding of the `SessionTicket` has changed.

The `SessionCache` and resumption handshake behavior is changed. `SessionCache` is renamed to `SessionStore` and intended to return on calls "immediately". If the `SessionStore` is not used, the `InMemoryConnectionStore` limits the number of connection per session to one. That results in cleanup additionally connection earlier than with an `SessionStore`. That behavior without `SessionStore` is very close to that of the 2.6., except, that failing handshakes using the same ip-address/port as the current connection will not remove this current connection. Using the `SessionStore` changes the behavior of 2.6 more. Some connections may be cleaned up later by eviction of the least recently used connection. And the `SessionStore` is assumed to be weakly consistent, without it's strictly consistent.

Please Note: the new `SessionStore` feature is not well tested! If used and causing trouble, don't hesitate to create an issue.

The `DTLSSession` is split into `DTLSContext` (connection/association specific data) and `DTLSSession` (session only data).

The `ApplicationLevelInfoSupplier.getInfo()` supports now to return `null` in order to not alter the additional information.

The `ResumingServerHandshaker` supports now a none-blocking `ResumptionVerifier` and a fallback to a full handshake.

The `CertificateProvider` introduces the possibility to use multiple certificates.

The `SignatureAndHashAlgorithm` supports now `isRecommended` to address the upcoming 
[draft-ietf-tls-md5-sha1-deprecate](https://datatracker.ietf.org/doc/draft-ietf-tls-md5-sha1-deprecate/).

The lifetime of cookies, used during initial stateless phase of a handshake, is reduced from 5 minutes to 1 minute. With the already available support for the past cookie, a HELLO_VERIFY_REQUEST is valid from 1 minute up to 2 minutes. The CLIENT_HELLO deduplication filter is extended from 1 minute to 2m15s. The intention is a slightly improvement of protection against spoofed CLIENT_HELLOs. 

### Californium-Core:

`MessageObserver.onAcknowledgement()`:

Since 3.0 this is only called for separate ACKs, not longer for piggy-backed responses.

The local address of the receiving endpoint is now a separate field, the usage of the destination context for incoming messages is replaced by that. Affects `CoapUriTranslator.getExposedInterface(Request)`.  This `Message.localAddress` also supports `UDPCOnnector` with `MulticastReceivers`.

`Blockwise Implementation` [RFC 7959](https://tools.ietf.org/html/rfc7959):

Since 3.0 the blockwise implementation has been redesigned. That includes the blockwise request/response matching, which is not longer based on the block's `num` in the Block Option [RFC 7959 - 2.2.  Structure of a Block Option](https://tools.ietf.org/html/rfc7959#section-2.2). It's now based on the calculated block's offset `num * size` [IETF core-mailing list](https://mailarchive.ietf.org/arch/msg/core/z9_HsDxAQJ17cqFwz2QhViOsZDI/).
Using the "transparent blockwise mode" (MAX_RESOURCE_BODY_SIZE larger than 0) in mix with application block options seems to be not completely defined. There are currently two use-cases, block2 early negotiation, and "random block access". But it seems to be hard, to document and test, what is exactly the API for such a mixed usage. Please consider to disable the "transparent blockwise mode" (MAX_RESOURCE_BODY_SIZE with 0), if application block options are required. Maybe these mixed (corner) cases gets discussed in a future version of Californium.

`Message.getPayload()`:

Since 3.0 `null` is replaced by `Bytes.EMPTY`. The method will now always return an byte array, which may be empty.

`Request.setOnResponseError(Throwable error)` is not longer accompanied by `Request.setCanceled(boolean canceled)`.

`Option(int number)`:

Since 3.0, the value is not initialized and must be provided with a separate setter call or using a other `Option` constructor. Though the 3.0 will now validate the option value, using `Bytes.EMPTY` as default would fail in too many cases.

The `OptionSet` and the `Option`s are now strictly validated. If that cause trouble, please check, if the value is valid according [RFC 7252, 5.10.  Option Definitions](https://tools.ietf.org/html/rfc7252#page-53) or the other specific RFCs.

[RFC 7967, Option for No Server Response](https://tools.ietf.org/html/rfc7967) is introduced.

Changing network configuration values during runtime is not supported by Californium's components. Therefore the `NetworkConfigObserver` is now removed.

### Californium-Proxy2:

The apache http-components have been updated to http-client 5.0.3 and http-core 5.0.2.
That requires to update all custom cross-proxy implementations as well.
Please consider the migration information on the [apache http-components web-page](https://hc.apache.org/)

The updated proxy2 now processes more coap-options and http-headers.

## Noteworthy API Changes

### Element-Connector:

1) The `ExtendedConnector` interface is integrated in `Connector`.

2) The `EndpointContext` supports now `String`, `Number`, and `Bytes`.

3) The `MulticastReceivers` interface (californium-core) is integrated in `UDPConnector`.

4) The `UdpMulticastConnector` must be build using `UdpMulticastConnector.Builder.setMulticastReceiver(true)` in order to be added and used as mutlicast receiver to a `UDPConnector`.

5) The `SslContextUtil.configure(String, String)` is removed, use `SslContextUtil.configure(String, KeyStoreType)` instead. `KeyStoreType` requires now either a type for the java `KeyStore` implementation, or a `SimpleKeyStore` custom reader.

### Scandium:

1) `PskStore`, `StaticPskStore`, `StringPskStore` and `InMemoryPskStore`

are removed and must be replaced by

`AdvancedPskStore`, `AdvancedSinglePskStore` and `AdvancedMultiPskStore`.

2) `TrustedRpkStore`, `TrustAllRpks`, `InMemoryRpkTrustStore`, `CertificateVerifier`, and `AdvancedCertificateVerifier`

are removed and must be replaced by

`NewAdvancedCertificateVerifier`, and `StaticNewAdvancedCertificateVerifier`.

3) The `DTLSession` in `NewAdvancedCertificateVerifier.verifyCertificate` is removed. Therefore the `InetSocketAddress` of the remote peer has been added. The parameter `Boolean clientUsage` is replaced by `boolean clientUsage`. With that, the key-usage extension is always checked, if provided.

4) `MtuUtil` is removed and must be replaced by `NetworkInterfacesUtil`.

5) The `ConnectionExecutionListener` interface is integrated in `ConnectionListener`.

6) The DTLSSession is split into `DTLSSession` and `DTLSContext`.

7) The `SessionListener` interface is adapted, `sessionEstablished` is now `contextEstablished`.

8) `useKeyUsageVerification` is removed from configuration. The key-usage extension is always checked, if provided.

9) `useHandshakeStateValidation` is removed from configuration. The handshake-state machine is now always.

10) The `ClientSessionCache` is removed and replaced by the `DTLSSession` serialization. The extended `ConnectionListener` and the `DTLSConnector.restoreConnection(Connection connection)` are for saving and restoring `Connection`s.

11) The `SessionCache` is renamed into `SessionStore`. It's now part of the `DtlsConnectorConfig` and not longer a parameter of the constructor for the `DTLSConnector`. `SessionStore.get(SessionId)` returns now a `DTLSSession` instead of the now obsolete  and removed `SessionTicket`.

12) The `ResumptionSupportingConnectionStore.remove(Connection)` is removed, use `ResumptionSupportingConnectionStore.remove(Connection, boolean)` and provided explicit, if the session is to be removed from the session store as well.

13) The `ResumptionSupportingConnectionStore.find(SessionId)` returns now a new DTLSSession instead of a connection.

14) Change `useNoServerSessionId` into `useServerSessionId` with inverse logic.

15) To support [RFC 7627, Extended Master Secret](https://tools.ietf.org/html/rfc7627), a parameter `useExtendedMasterSecret` is added to
`AdvancedPskStore.requestPskSecretResult`.

16) Change `DtlsConnectorConfig.getPrivateKey`, `getPublicKey`, and `getCertificateChain` are replaced by the introduced `CertificateProvider`. `DtlsConnectorConfig.getCertificateIdentityProvider` is added to access the `CertificateProvider`. The `SingleCertificateProvider` is provided, if only  a single certificate based identity is required. The related setters in the `DtlsConnectorConfig.Builder` are replaced also by `setCertificateIdentityProvider`.

### Californium-Core:

1) The `MessageObserver2` interface is integrated in `MessageObserver`.

2) The `InternalMessageObserver` interface is integrated in `MessageObserver`.

3) The `InternalMessageObserverAdapter` is integrated in `MessageObserverAdapter`.

4) The `InternalMessageObserverAdapter` interface is integrated in `MessageObserverAdapter`.

5) `CoapEndpointHealth` and `CoapEndpointHealthLogger`

are removed and must be replaced by

`HealthStatisticLogger`

6) The `MessagePostProcessInterceptors` interface is integrated in `Endpoint`.

7) The `MulticastReceivers` interface is moved into `UDPConnector`.

8) Renamed `Message.onComplete()` to `onTransferComplete()`, including `MessageObserver.onComplete()`.

9) Changed `Exchange.getRetransmissionHandle()` to `isTransmissionPending()`.

10) Add `DelivererException` to `ServerMessageDeliverer.findResource(Exchange exchange)` and `ServerMessageDeliverer.findResource(List<String> list)`

11) Change the return type of `MediaTypeRegistry.parseWildcard(String wildcard)` from `Integer[]` to `int[]`.

12) Removed `Resource.getSecondaryExecutor()` and change the return type of `Resource.getExecutor()` from `ExecutorService` to the simpler `Executor`. Specific `Resource` implementation may maintain the executors as required by them.

13) Removed `CoapResource.createClient(???)`. Though `Resource.getExecutor()` may return `null`, it depends on the implementation of the `Resource` not to return `null`, but that changes other executions. Therefore implement `createClient(???)` for the specific `Resources` and provide the executors there. 

14) Removed `CoapEndpoint.Builder.setConnectorWithAutoConfiguration(UDPConnector)`. `Configuration` must now be provided to the Connector's constructors.

### Californium-Proxy2:

1) Update to http-client 5.0.3 and http-core 5.0.2. The apache http-components are not encapsulated. Therefore this update causes several API changes, where these classes are used. Please consider the migration information on the [apache http-components web-page](https://hc.apache.org/)

2) Add package `org.eclipse.californium.proxy2.http` and moved all http-translation relevant classes into that. Rename `HttpTranslator` into `CrossProtocolTranslator`

3) Add package `org.eclipse.californium.proxy2.http.server` and moved the http-server specific classes into that.
