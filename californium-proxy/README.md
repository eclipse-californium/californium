# Vulnerability - CVE-2018-10237

```
CVE-2018-10237
moderate severity
Vulnerable versions: > 11.0, < 24.1.1
Patched version: 24.1.1
```

Unbounded memory allocation in Google Guava 11.0 through 24.x before 24.1.1 allows remote attackers to conduct denial of service attacks against servers that depend on this library and deserialize attacker-provided data, because the AtomicDoubleArray class (when serialized with Java serialization) and the CompoundOrdering class (when serialized with GWT serialization) perform eager allocation without appropriate checks on what a client has sent and whether the data size is reasonable.

## Californium - Proxy

The vulnerable `AtomicDoubleArray` is not used directly by the californium-proxy. It's unknown, if it's used internally for the LoadingCache. In doubt, please consider to use californium-proxy2. That not only comes with an updated guava (28.2), it comes also with more flexible support for reverse-proxies and compliant forward-proxy implementation.
