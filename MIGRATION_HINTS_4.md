![Californium logo](cf_64.png)

# Californium (Cf) - Migration Hints

October, 2024

The version 3.x is now out for about more than three years and reached version 3.13.0.
I have started to work on a 4.0 on October 2024 starting with removing deprecates APIs.

To migrate to the 4.0 this gives some hints to do so. If you miss something, don't hesitate to create an issue.

Please, keep in mind, that the 4.0 API is under develop.

## General

This document doesn't contain hints for migrating versions before 3.0. That excludes also hints to migrate any of the 3.0 MILESTONE releases.

If a 3.0.0 or newer is used, it's recommended to update first to 3.13.0 and cleanup all deprecation using the documentation on the deprecation.

Some of the configuration properties are not longer supported (they have been marked as deprecated) and it is recommended to generate new property files and compare the content with the ones previous in use.

## Base Lines

The plan is still to be able to use Californium with java 8. 
That requires also to use Android 8, API level 26. According a discussion, it is possible to [desugaring](https://github.com/eclipse-californium/californium/issues/1664#issuecomment-1893991987) java 8 back to Android versions before

For a local build new Java versions will be required. For now I would consider to
support java 17 as minimum version to build Californium.

## Noteworthy Behavior Changes

### Element-Connector:

### Scandium:

Additional to the deprecated marked API, the implementation of the features are also removed.

The functions to reduce the HelloVerifyRequests for specific cases, PSK (`DTLS_USE_HELLO_VERIFY_REQUEST_FOR_PSK`) and resumption handshakes (`DTLS_VERIFY_PEERS_ON_RESUMPTION_THRESHOLD`)have been removed. The general function (`DTLS_USE_HELLO_VERIFY_REQUEST`) to disable it is still available. The unit-test have been updated according this changed behavior.

The functions to handle the "deprecated CID" definition in the drafts before the RFC9146 have been removed. If still used in some other implementations, please update those other implementations to the final RFC.

The removing of the deprecated function `DTLSConnector.onInitializeHandshaker` showed, that a single custom `SessionListener` is not enough, if a derived class has overridden it. Therefore `DTLSConnector.addSessionListener` has been added.

### Element-Connector-TCP-Netty:

### Californium-Core:

### Californium-Proxy2:

## Noteworthy API Changes

### Element-Connector:

### Scandium:

The removing of the deprecated function `DTLSConnector.onInitializeHandshaker` showed, that a single custom `SessionListener` is not enough, if a derived class has overridden it. Therefore `DTLSConnector.addSessionListener` has been added.

Removing the HelloVerifyRequests for specific cases obsoletes also `ResumptionVerifier.skipRequestHelloVerify` and `ExtendedResumptionVerifier`. Also the last parameter of `DtlsHealth.dump` is removed.

The functions of the obsolete and removed `DtlsHealthExtended` and `DtlsHealthExtended2` are moved into
`DtlsHealth`.

The functions of the obsolete and removed `DatagramFilterExtended` are moved into
`DatagramFilter`.

### Californium-Core:

The functions of the obsolete and removed `ExtendedCoapStack` are moved into
`CoapStack`.

### Californium-Proxy2:

