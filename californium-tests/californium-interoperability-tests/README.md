![Californium logo](../../cf_64.png)

# Californium (Cf) - Interoperability Tests

_Californium (Cf)_  is commonly used only on one side, e.g. as server or client, and an other implementation is used on the other side.

These  _Californium (Cf) - Interoperability Tests_  are intended to ensure interoperability with [libcoap](https://github.com/obgm/libcoap) with `gnutls`, `openssl`, `mbedtls` and `tinydtls` DTLS 1.2 bindings.

Additionally, [Mbed-TLS](https://github.com/Mbed-TLS/mbedtls), [openssl](https://github.com/openssl/openssl) and [tinydtls](https://github.com/eclipse/tinydtls) are tested for interoperability on their own.

# Usage

This _Interoperability Tests_  requires to have some binaries build and installed ahead.

For [libcoap](https://github.com/obgm/libcoap) you will find some notes in [LibCoapProcessUtil](src/test/java/org/eclipse/californium/interoperability/test/libcoap/LibCoapProcessUtil.java#L42-L87). The DTLS bindings requires also to install the DTLS libraries in order to build libcoap with that binding.

For [openssl](https://github.com/openssl/openssl) some notes are in [OpenSslProcessUtil](src/test/java/org/eclipse/californium/interoperability/test/openssl/OpenSslProcessUtil.java#L42-L61)

For [Mbed-TLS](https://github.com/Mbed-TLS/mbedtls) some notes are in [MbedTlsProcessUtil](src/test/java/org/eclipse/californium/interoperability/test/mbedtls/MbedTlsProcessUtil.java#L39-L58)

For [tinydtls](https://github.com/eclipse/tinydtls) some notes are in [TinydtlsProcessUtil](src/test/java/org/eclipse/californium/interoperability/test/tinydtls/TinydtlsProcessUtil.java#L28-L38). Ensure to use the ""feature/connection_id" to enable DTLS 1.2 CID support.

When the binaries a build and install in the "PATH", the tests are execute using

```
mvn test
```

This executes a common set of DTLS parameters. If you want more complete tests, use

```
mvn test -DINTENSIVE_TESTS=true
```

If you want to test the interoperability usingthe [Bouncy Castle JCE](https://github.com/bcgit/bc-java) use

```
mvn test -Pbc-tests
```

Both options may be used together.

## Testing for randomly occurring failures

DTLS 1.2 uses handshake with some random artifacts, e.g. ECDHE uses ephemeral EC keys. Especially encoding errors in that parts are hard to find. Using the []() makes it simpler to execute the test much more times in order to check, if such a random failure occurs.

Californium comes for that case with the [RepeatingTestRunner](https://github.com/eclipse-californium/californium/blob/main/element-connector/src/test/java/org/eclipse/californium/elements/runner/RepeatingTestRunner.java) and the [ParameterizedRepeatingTestRunner](https://github.com/eclipse-californium/californium/blob/main/element-connector/src/test/java/org/eclipse/californium/elements/runner/ParameterizedRepeatingTestRunner.java). Using them requires to edit the interop-tests, which are intended to be run multiple times. 

```
 * @since 3.3
 */
@RunWith(RepeatingTestRunner.class)
public class MbedTlsClientAuthenticationInteroperabilityTest {
```

Adding `@RunWith(RepeatingTestRunner.class)` marks the test for that.
The default is 100 times and using 

```
mvn test -Dorg.eclipse.californium.elements.runner.TestRepeater.repeats=1000
```

enables to select an other number, here 1000.

# Testing Interoperability Of Specific Versions

Just in the case someone needs to test with specific versions of the other implementations, that may work "out of the box" or not. Some of the libraries have bugs in single features on single versions so a failure requires then analysis and the knowledge to do so. Sometimes the CLI-API is changing, so also be careful with that.
