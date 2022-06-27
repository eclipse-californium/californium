![Californium logo](../../cf_64.png)

# Californium (Cf) - Plugtest Server

Californium contains a plugtest server, that implements the test specification for the ETSI IoT, CoAP Plugtests, London, UK, 7--9 Mar 2014.

## General Usage

Start the [cf-plugtest-server-3.6.0.jar](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-plugtest-server/3.6.0/cf-plugtest-server-3.6.0.jar) with:

```sh
java -jar cf-plugtest-server-3.6.0.jar -h

Usage: PlugtestServer [-h] [--dtls-only] [--[no-]echo-delay] [--[no-]external]
                      [--[no-]ipv4] [--[no-]ipv6] [--[no-]loopback] [--[no-]
                      oscore] [--[no-]tcp] [--trust-all]
                      [--client-auth=<clientAuth>]
                      [--notify-interval=<notifyInterval>]
                      [--interfaces-pattern=<interfacePatterns>[,
                      <interfacePatterns>...]]... [--store-file=<file>
                      [--store-password64=<password64>]
                      --store-max-age=<maxAge>]
      --client-auth=<clientAuth>
                            client authentication. Values NONE, WANTED, NEEDED.
      --dtls-only           only dtls endpoints.
      --[no-]echo-delay     enable delay option for echo resource.
  -h, --help                display a help message
      --interfaces-pattern=<interfacePatterns>[,<interfacePatterns>...]
                            interface regex patterns for endpoints.
      --[no-]external       enable endpoints on external network.
      --[no-]ipv4           enable endpoints for ipv4.
      --[no-]ipv6           enable endpoints for ipv6.
      --[no-]loopback       enable endpoints on loopback network.
      --[no-]oscore         use OSCORE.
      --[no-]tcp            enable endpoints for tcp.
      --notify-interval=<notifyInterval>
                            Interval for plugtest notifies. e.g. 5[s]. Minimum 5
                              [ms], default 5000[ms].
      --store-file=<file>   file store dtls state.
      --store-max-age=<maxAge>
                            maximum age of connections in hours.
      --store-password64=<password64>
                            password to store dtls state. base 64 encoded.
      --trust-all           trust all valid certificates.
```

To see the set of options and arguments.

## DTLS Graceful Restart

The plugtest server is extended to "save" the DTLS connection state (into memory) and "load" it again. For demonstration, type

```
save
```

into the console of the server.

```
> save
???:39.664 INFO [CoapServer]: PLUG-TEST Stopping server ...
???:39.778 INFO [CoapServer]: PLUG-TEST Stopped server.
???:39.779 INFO [PersistentComponentUtil]: saved: 0 items of dtls://[2a02:8070:4a7:f780:67c7:c2c9:4266:3e03%25enp7s0]:5684
???:39.793 INFO [PersistentComponentUtil]: saved: 2000 items of dtls://127.0.0.1:5684
???:39.793 INFO [PersistentComponentUtil]: save: 14 ms, 2000 connections
???:39.793 INFO [CoapServer]: Saved: 593261 Bytes
```

The connections will be saved and removed from the connector. The benchmark client will show a significant smaller number of requests. Now load the connections again, type

```
load
```

into the console of the server.

```
> load
???:22.676 INFO [PersistentComponentUtil]: loading dtls://[2a02:8070:4a7:f780:67c7:c2c9:4266:3e03%25enp7s0]:5684, 0 items, 2 components.
???:22.707 INFO [PersistentComponentUtil]: loading dtls://127.0.0.1:5684, 2000 items, 2 components.
???:22.707 INFO [PersistentComponentUtil]: load: 31 ms, 2000 items
???:22.707 INFO [CoapServer]: Loaded: 593261 Bytes
???:22.707 INFO [CoapServer]: PLUG-TEST Starting server
```

It's also possible to restart the server, if the arguments `--store-file` (filename to save and load the states), `--store-password64` (base64 encoded password to save and load the states), and `--store-max-age` (maximum age of connections to be stored. Value in hours) are provided. To demonstrate, type

```
exit
```

into the console of the server.

```
> exit
???:21.132 INFO [CoapServer]: PLUG-TEST Stopping server ...
???:21.168 INFO [CoapServer]: PLUG-TEST Stopped server.
???:21.210 INFO [CoapServer]: Executor shutdown ...
???:21.211 INFO [CoapServer]: Thread [1] main
???:21.211 INFO [CoapServer]: Thread [144] globalEventExecutor-1-4
???:22.213 INFO [CoapServer]: Exit ...
???:22.214 INFO [CoapServer]: Shutdown ...
???:22.309 INFO [ServersSerializationUtil]: save: 21 ms, 2000 connections
???:22.310 INFO [CoapServer]: Shutdown.
```

and then start the server again using the same `--store-file` and `--store-password64` as before and also provide the `--store-max-age` for the next restart.

Note: if it takes too long between "save" and "load", the clients will detect a timeout and trigger new handshakes. So just pause a small couple of seconds!

Note: only the DTLS state is persisted. To use this feature, the client is intended to use mainly CON request and the server the use piggybacked responses. Neither DTLS handshake, separate responses, observe/notifies, nor blockwise transfers are supported.
