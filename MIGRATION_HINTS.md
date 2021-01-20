![Californium logo](cf_64.png)

# Californium (Cf) - Migration Hints

December, 2020

The version 2.x is now out for about a year and reached version 2.6.0.
We currently started to work on a 3.0 starting with removing deprecates APIs.

To migrate to the 3.0 this gives some hints to do so. If you miss something, don't hesitate to create an issue.

Please, keep in mind, that the 3.0 API is under develop.

## General

This document doesn't contain hints for migrating versions before 2.0. That excludes also hints to migrate any of the 2.0 MILESTONE releases.

If a 2.0.0 or newer is used, it's recommended to update first to 2.6.0 and cleanup all deprecation using the documentation on the deprecation.

## Noteworthy Behavior Changes

### Californium-Core:

`MessageObserver.onAcknowledgement()`:

Since 3.0 this is only called for separate ACKs, not longer for piggy-backed responses.

### Element-Connector:

`Bytes.equals(Object other)`:

Since 3.0 the sub-class may be ignored, depending on the provided value of the `useClassInEquals` parameter in `Bytes(byte[], int, boolean, boolean)`. The default behavior is changed to ignore the sub-class.

## Noteworthy API Changes

### Element-Connector:

1) The `ExtendedConnector` interface is integrated in `Connector`.

2) The `EndpointContext` supports now `String`, `Number`, and `Bytes`.

### Scandium:

1) `PskStore`, `StaticPskStore`, `StringPskStore` and `InMemoryPskStore`

are removed and must be replaced by

`AdvancedPskStore`, `AdvancedSinglePskStore` and `AdvancedMultiPskStore`.

2) `TrustedRpkStore`, `TrustAllRpks`, `InMemoryRpkTrustStore`, `CertificateVerifier`, and `AdvancedCertificateVerifier`

are removed and must be replaced by

`NewAdvancedCertificateVerifier`, and `StaticNewAdvancedCertificateVerifier`.

3) The `DTLSession` in `NewAdvancedCertificateVerifier.verifyCertificate` is removed. If that is required by your implementation, please open an issue.

4) `MtuUtil` is removed and must be replaced by `NetworkInterfacesUtil`.

5) The `ConnectionExecutionListener` interface is integrated in `ConnectionListener`.

6) The DTLSSession is split into `DTLSSession` and `DTLSContext`.

7) The `SessionListener` interface is adapted, `sessionEstablished` is now `contextEstablished`.

### Californium-Core:

1) The `MessageObserver2` interface is integrated in `MessageObserver`.

2) The `InternalMessageObserver` interface is integrated in `MessageObserver`.

3) The `InternalMessageObserverAdapter` is integrated in `MessageObserverAdapter`.

4) The `InternalMessageObserverAdapter` interface is integrated in `MessageObserverAdapter`.

5) `CoapEndpointHealth` and `CoapEndpointHealthLogger`

are removed and must be replaced by

`HealthStatisticLogger`

6) The `MessagePostProcessInterceptors` interface is integrated in `Endpoint`.

7) The `MulticastReceivers` interface is integrated in `Endpoint`.
