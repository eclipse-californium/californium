![Californium logo](cf_64.png)

# Californium (Cf) - Migration Hints

February, 2021

The version 2.x is now out for about a year and reached version 2.6.0.
We currently started to work on a 3.0 starting with removing deprecates APIs.

To migrate to the 3.0 this gives some hints to do so. If you miss something, don't hesitate to create an issue.

Please, keep in mind, that the 3.0 API is under develop.

## General

This document doesn't contain hints for migrating versions before 2.0. That excludes also hints to migrate any of the 2.0 MILESTONE releases.

If a 2.0.0 or newer is used, it's recommended to update first to 2.6.0 and cleanup all deprecation using the documentation on the deprecation.

## Noteworthy Behavior Changes

### Element-Connector:

`Bytes.equals(Object other)`:

Since 3.0 the sub-class may be ignored, depending on the provided value of the `useClassInEquals` parameter in `Bytes(byte[], int, boolean, boolean)`. The default behavior is changed to ignore the sub-class.

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

### Californium-Core:

`MessageObserver.onAcknowledgement()`:

Since 3.0 this is only called for separate ACKs, not longer for piggy-backed responses.

The local address of the receiving endpoint is now a separate field, the usage of the destination context for incoming messages is replaced by that. Affects `CoapUriTranslator.getExposedInterface(Request)`.

`Blockwise Implementation` [RFC 7959](https://tools.ietf.org/html/rfc7959):

Since 3.0 the blockwise implementation has been redesigned. That includes the blockwise request/response matching, which is not longer based on the block's `num` in the Block Option [RFC 7959 - 2.2.  Structure of a Block Option](https://tools.ietf.org/html/rfc7959#section-2.2). It's now based on the calculated block's offset `num * size` [IETF core-mailing list](https://mailarchive.ietf.org/arch/msg/core/z9_HsDxAQJ17cqFwz2QhViOsZDI/)

`Message.getPayload()`:

Since 3.0 `null` is replaced by `Bytes.EMPTY`. The method will now always return an byte array, which may be empty.

## Noteworthy API Changes

### Element-Connector:

1) The `ExtendedConnector` interface is integrated in `Connector`.

2) The `EndpointContext` supports now `String`, `Number`, and `Bytes`.

3) The `MulticastReceivers` interface (californium-core) is integrated in `UDPConnector`.

4) The `UdpMulticastConnector` must be build using `UdpMulticastConnector.Builder.setMulticastReceiver(true)` in order to be added and used as mutlicast receiver to a `UDPConnector`.

### Scandium:

1) `PskStore`, `StaticPskStore`, `StringPskStore` and `InMemoryPskStore`

are removed and must be replaced by

`AdvancedPskStore`, `AdvancedSinglePskStore` and `AdvancedMultiPskStore`.

2) `TrustedRpkStore`, `TrustAllRpks`, `InMemoryRpkTrustStore`, `CertificateVerifier`, and `AdvancedCertificateVerifier`

are removed and must be replaced by

`NewAdvancedCertificateVerifier`, and `StaticNewAdvancedCertificateVerifier`.

3) The `DTLSession` in `NewAdvancedCertificateVerifier.verifyCertificate` is removed. If that is required by your implementation, please open an issue. The parameter `Boolean clientUsage` is replaced by `boolean clientUsage`. With that, the key-usage extension is always checked, if provided.

4) `MtuUtil` is removed and must be replaced by `NetworkInterfacesUtil`.

5) The `ConnectionExecutionListener` interface is integrated in `ConnectionListener`.

6) The DTLSSession is split into `DTLSSession` and `DTLSContext`.

7) The `SessionListener` interface is adapted, `sessionEstablished` is now `contextEstablished`.

8) `useKeyUsageVerification` is removed from configuration. The key-usage extension is always checked, if provided.

9) `useHandshakeStateValidation` is removed from configuration. The handshake-state machine is now always.

10) The `ClientSessionCache` is removed and replaced by the `DTLSSession` serialization. The extended `ConnectionListener` and the `DTLSConnector.restoreConnection(Connection connection)` are for saving and restoring `Connection`s.

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
