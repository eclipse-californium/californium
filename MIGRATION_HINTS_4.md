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

The major update is also used to simplify some names, which have grown in length over the time. With removing alternative implementations these names has also be shortened.

## Base Lines

The plan is still to be able to use Californium with java 8. 
That requires also to use Android 8, API level 26. According a discussion, it is possible to [desugaring](https://github.com/eclipse-californium/californium/issues/1664#issuecomment-1893991987) java 8 back to Android versions before. 

**Note:** as for now (January 2025) the android example doesn't compile anymore. if that gets fixed in the future depends the on the interest and contribution.

For a local build new Java versions will be required. For now I would consider to
support java 17 as minimum version to build Californium.

## Noteworthy Behavior Changes

Californium 3 used in several functions two `ScheduledExecutorService` for execution. The main was intended to be used only for very short and fast tasks in a "non-blocking" way. The "scheduled" tasks of that main executor are mainly intended to switch then to {@link SerialExecutor} to serialize executing jobs in the scope of an (CoAP) `Exchange` (DTLS) `Conection` secondary executor is the intended for longer running tasks, e.g. cleanup jobs. This long jobs must not execute too frequently and may be delayed. To optimize the performance the main executor should be created with `ExecutorsUtil.newScheduledThreadPool(int, ThreadFactory)` and the secondary with `ExecutorsUtil.newDefaultSecondaryScheduler(String)`.

In order to simplify the API for Californium 4, this behavior is mapped into the `ProtocolScheduledExecutorService` interface. This replaces the two executors in several functions. It may be provided with a custom implementation or by `ExecutorsUtil.newProtocolScheduledThreadPool(int, ThreadFactory)` and
`ExecutorsUtil.newSingleThreadedProtocolExecutor(ThreadFactory)`.

Californium 4 uses `Option` with immutable values. Customized implementations are intended to provide their `OptionDefinition` as a static inner class of the `Option`. The `Option` implementations are moved into a separate package, which cases some adaptions in the import declarations.

### Element-Connector:

Supports virtual threads for UDP receivers and senders, if the JVM supports it. Otherwise platform daemon threads are used. Chosen by `-1` as number of threads in `UDP.RECEIVER_THREAD_COUNT` and `UDP.SENDER_THREAD_COUNT`.

### Scandium:

Additional to the deprecated marked API, the implementation of the features are also removed.

The functions to reduce the HelloVerifyRequests for specific cases, PSK (`DTLS_USE_HELLO_VERIFY_REQUEST_FOR_PSK`) and resumption handshakes (`DTLS_VERIFY_PEERS_ON_RESUMPTION_THRESHOLD`)have been removed. The general function (`DTLS_USE_HELLO_VERIFY_REQUEST`) to disable it is still available. The unit-test have been updated according this changed behavior.

The functions to handle the "deprecated CID" definition in the drafts before the RFC9146 have been removed. If still used in some other implementations, please update those other implementations to the final RFC.

With this major version the DTLS 1.2 Connection ID is enabled by default with a length of 6 bytes. Therefore using the default by using an `<empty>` value will not longer work to disable this feature. Please use `-1`, if you want to disable it.

The removing of the deprecated function `DTLSConnector.onInitializeHandshaker` showed, that a single custom `SessionListener` is not enough, if a derived class has overridden it. Therefore `DTLSConnector.addSessionListener` has been added.

In some cases `SHA384` was misspelled as `SHA378`. That's fixed but causes also to fail reading old `Californium3.properties`. 

Supports virtual threads for DTLS receivers, if the JVM supports it. Otherwise platform daemon threads are used. Chosen by `-1` as number of threads in `DTLS.RECEIVER_THREAD_COUNT`.

The `DTLSConnector` uses Connection ID to identify DLTS context now also for outgoing messages, if available.

The `DefaultCipherSuiteSelector` supports now `CertificateAuthenticationMode.WANTED` even if no common client certificate type is available. It omits the `CertificateRequest` in this case.

The `InMemoryConnectionStore` removes now `Connection`s without `Principals` when the ip-address is reused.

Using the `DTLS.APPLICATION_AUTHORIZATION_TIMEOUT` removes now connections with anonymous clients after that timeout, if the application doesn't authorize them using the `ApplicationAuthorizer`.

### Element-Connector-TCP-Netty:

### Californium-Core:

The `Option` is changed to be immutable, removing the setters.

The `OptionSet` uses now instances of `Option` subclasses instead of the representing java types.

The `DataParser` and `DataSerializer` detect multiple ETAGs in responses and reject such
messages.

### Californium-Proxy2:

The apache http libraries haven been update to http-client 5.4 and http-core 5.3. The previous version used a pre-processing filter to implement a generic proxy (catch all), which added the path "proxy" to the incoming request. With this update the `RequestRouter` is used and so the routing may have changed slightly according the details. The proxy handler is now called with the original path without additional "proxy".

The http-client 5.4 follows [RFC 7540, 8.1.2.3, Request Pseudo-Header Fields](https://www.rfc-editor.org/rfc/rfc7540#section-8.1.2.3) and deprecates the use of a "userinfo" field. Such request will fail.

## Noteworthy API Changes

### Element-Connector:

Removed `StringUtil.toHostString()` (support Java 6). Java 8 is the minimum supported version for runtime, therefore use `InetSocketAddress.getHostString()` directly.

Removed `org.eclipse.californium.elements.util.StandardCharsets`, obsoleted by java 8 `java.nio.charset.StandardCharsets`.

Removed `org.eclipse.californium.elements.util.Filter`, obsoleted by java 8 `java.util.function.Predicate`.

Removed `org.eclipse.californium.elements.util.Base64`, obsoleted by java 8 `java.util.Base64`.

`org.eclipse.californium.elements.util.StringUtil.base64ToByteArray(String)` throws now `IllegalArgumentException` for invalid content instead of returning an empty array.

Introduce `ProtocolScheduledExecutorService` interface to simplify main and secondary executors.

Add `ExecutorsUtil.newProtocolScheduledThreadPool(int, ThreadFactory)` and
`ExecutorsUtil.newSingleThreadedProtocolExecutor(ThreadFactory)` to created implementations of `ProtocolScheduledExecutorService`.

### Scandium:

The removing of the deprecated function `DTLSConnector.onInitializeHandshaker` showed, that a single custom `SessionListener` is not enough, if a derived class has overridden it. Therefore `DTLSConnector.addSessionListener` has been added.

Removing the HelloVerifyRequests for specific cases obsoletes also `ResumptionVerifier.skipRequestHelloVerify` and `ExtendedResumptionVerifier`. Also the last parameter of `DtlsHealth.dump` is removed.

The functions of the obsolete and removed `DtlsHealthExtended` and `DtlsHealthExtended2` are moved into
`DtlsHealth`.

The functions of the obsolete and removed `DatagramFilterExtended` are moved into
`DatagramFilter`.

Change scope of `DTLSFlight.wrapMessage` to `private`.

The names `CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA378`, and `CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA378` are corrected into `CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384`, and `CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384`. 

Merged `ReadWriteLockConnectionStore` into `ResumptionSupportingConnectionStore` and renamed this into `ConnectionStore`. Remove obsolete `ReadWriteLockConnectionStore`. Also renames `InMemoryReadWriteLockConnectionStore` into `InMemoryConnectionStore`.

Uses the new introduced `ProtocolScheduledExecutorService`.

Remove the "Advanced" from PSK-stores. Replace `AdvancedPskStore` by `PskStore`, `AdvancedSinglePskStore` by `SingelPskStore`, `AdvancedMultiPskStore` by `MultiPskStore`, and `AsyncAdvancedPskStore` by `AsyncPskStore`. Rename `advancedPskStore` field and variables into `pskStore`, `DtlsConnectorConfig.getAdvancedPskStore()` into `DtlsConnectorConfig.getPskStore()`, and `DtlsConnectorConfig.Builder.setAdvancedPskStore(AdvancedPskStore)` into `DtlsConnectorConfig.Builder.setPskStore(PskStore)`.

Remove the "NewAdvanced" from CertificateVerifier. Replace `NewAdvancedCertificateVerifier` by `CertificateVerifier`, `StaticNewAdvancedCertificateVerifier` by `StaticCertificateVerifier` and `AsyncNewAdvancedCertificateVerifier` by `AsyncCertificateVerifier`.

Rename `Connection.refreshAutoResumptionTime` into `updateLastMessageNanos`.

`DTLSConnector.cleanupRecentHandshakes` returns `int` instead of `void`.

Remove `restoreConnection` from `DTLSConnector`.

Replace `DtlsBlockConnectionState.getMac` by `DtlsBlockConnectionState.initMac`. Adapt `CbcBlockCipher.getBlockCipherMac()` to use a already initialized `Mac` and remove the `macKey` from the parameter list.

### Californium-Core:

The functions of the obsolete and removed `ExtendedCoapStack` are moved into
`CoapStack`.

Rename `ExtendedCoapStackFactory` into `CoapStackFactory`.

Remove setters from `Option`.

Introduce `OptionNumber` to compare `Option` and `OptionDefintion` based on their `number`.

Remove `CropRotation`. Please use an other available deduplication algorithms.

Remove `ResponseConsumer`. Replaced by `Consumer<Response>`.

`Endpoint`, `CoapServer`, `CoapClient`, `CoapStack`, and `Layer` replaces the main and secondary executor by the new introduced `ProtocolScheduledExecutorService`. Also replaces `void setExecutors(ScheduledExecutorService mainExecutor, ScheduledExecutorService secondaryExecutor)` by `void setExecutor(ProtocolScheduledExecutorService executor)`.

Add `Endpoint.getExecutor()`.

`ClientObserveRelation` and `CoapObserveRelation` switched to use the `Endpoint` executor instead of a separate argument.

The `Option.getStringValue()` and `Option.getIntegerValue()/getLongValue()` are moved to `StringOption` and `IntegerOption`. `Option.getValue()` is moved to `OpaqueOption` and replaced by `Option.encode()`. `Option.writeTo(DatagramWriter)` has been added. The `byte[]` constructors have been removed and only still available for `OpaqueOption`. The `assertValue` is moved into the classes derived from `Option`and `Option(OptionDefinition definition)`is the only left constructor.

The `BlockOption` and `NoResponseOption` moved into the `org.eclipse.californium.core.coap.option` package. Both now extends from `IntegerOption`. `byte[] BlockOption.encode(int szx, boolean m, int num)` is replaced by  `int BlockOption.encode(int szx, boolean m, int num)`.

The `StringOption` now extends `OpaqueOption`.

The specific `OptionDefinition`s are moved into static classes, e.g. `IntegerOptionDefinition` to `IntegerOption.Definition`. The `OptionDefinition.create(byte[] data)` is replaced by `OptionDefinition.create(DatagramReader reader, int lengt)`. `OptionDefinition.assertValue(byte[] data)` is replaced by `void OptionDefinition.assertValueLength(int length)` and `IntegerOption.Definition.assertValue(long value)`.

The `OptionSet` functions returning `List<String>` or `List<byte[]>` returns now `List<Stringoption>` or `List<OpaqueOption>`. `List<String> OptionSet.getValues(final List<StringOption> options)` has been added. `OptionSet.setBlock1(byte[] value)` and  `OptionSet.setBlock2(byte[] value)` have been removed.

The `assertValidOptions` function of `DataParser` and `DataSerializer` uses now a `Message` as parameter instead of an `OptionSet` to distinguish between requests and responses.

The `DataParser.createOption(int code, int optionNumber, DatagramReader reader, int length)` uses now a reader and length instead of a temporary byte array copy of the value.

### Californium-Proxy2:

Rename `HttpServer.registerVirtual` into `register`.

