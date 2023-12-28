![Californium logo](../../cf_64.png)

# Californium (Cf) - Simple File Server

Enable to use CoAP blockwise [RFC7959 - Block-Wise Transfers in the Constrained Application Protocol](http://tools.ietf.org/html/rfc7959).

## General

Please refer to the eclipse Californium project page for license, build, and install.

## Download

[Eclipse Release Repository](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-simplefile-server/3.10.0/cf-simplefile-server-3.10.0.jar)

## PREPARATION

Generate "Californium.properties" using 

```sh
java -jar cf-simplefile-server-<version>.jar
```

Adjust properties according you setup/environment, at least adjust "MAX_RESOURCE_BODY_SIZE"
to the largest file size you want to support. Make sure, this "Californium3.properties" is then used on both sides, server and client.

Create a folder ("data" by default), and place the file(s) in that folder.

## RUN

```sh
java -jar cf-simplefile-server-<version>.jar [--file-root=<file-root-directory>] [--path-root=<coap-root>]
```

Default for both roots is: "data".
So mostly just create a folder "data", add your files to that sub folder and start the jar.

## GET

```sh
URL: coap://<host>/<coap-root>/<file-path>
```

e.g (using `cf-helloworld-client`)

```sh
java -jar cf-helloworld-client-<version>.jar GETClient coap://localhost/data/file.bin file2save.bin
```

(GET file "file.bin" from file-root-directory).

## Usage

```
Usage: SimpleFileServer [-h] [--dtls-only] [--[no-]external] [--[no-]ipv4] [--
                        [no-]ipv6] [--[no-]loopback] [--[no-]tcp] [--trust-all]
                        [--client-auth=<clientAuth>] [--file-root=<fileRoot>]
                        [--path-root=<pathRoot>]
                        [--interfaces-pattern=<interfacePatterns>[,
                        <interfacePatterns>...]]... [--store-file=<file>
                        [--store-password64=<password64>]
                        --store-max-age=<maxAge>]
      --client-auth=<clientAuth>
                            client authentication. Values NONE, WANTED, NEEDED.
      --dtls-only           only dtls endpoints.
      --file-root=<fileRoot>
                            files root. Default "data"
  -h, --help                display a help message
      --interfaces-pattern=<interfacePatterns>[,<interfacePatterns>...]
                            interface regex patterns for endpoints.
      --[no-]external       enable endpoints on external network.
      --[no-]ipv4           enable endpoints for ipv4.
      --[no-]ipv6           enable endpoints for ipv6.
      --[no-]loopback       enable endpoints on loopback network.
      --[no-]tcp            enable endpoints for tcp.
      --path-root=<pathRoot>
                            resource-path root. Default "data"
      --store-file=<file>   file store dtls state.
      --store-max-age=<maxAge>
                            maximum age of connections in hours.
      --store-password64=<password64>
                            password to store dtls state. base 64 encoded.
      --trust-all           trust all valid certificates.
```

Examples:

File system:

```
/home/cali/data/cf_64.png
               /README.md
               /fw/device.hex
```

Options:

```
--file-root=/home/cali/data
--path-root=files
```

With that, the file system tree below `/home/cali/data` is used and the sub-path of URIs `coap://<host>/files/<sub-path>` are used to locate the file within that tree.

```
java -jar cf-simplefile-server-<version>.jar --file-root=/home/cali/data --path-root=files --no-tcp

INFO [SimpleFileServer]: GET: coap://<host>/files/cf_64.png
INFO [SimpleFileServer]: GET: coap://<host>/files/README.md
INFO [SimpleFileServer]: GET: coap://<host>/files/fw/device.hex
```

```
java -jar cf-helloworld-client-<version>.jar GETClient coap://localhost/files/cf_64.png picture2save.png
java -jar cf-helloworld-client-<version>.jar GETClient coap://localhost/files/fw/device.hex firmware.hex
```

Access files out of the file system sub-tree results in an error response.
 
```
java -jar cf-helloworld-client-<version>.jar GETClient coap://localhost/files/../../other/top-secret.txt steal.txt

4.01 - UNAUTHORIZED
```
