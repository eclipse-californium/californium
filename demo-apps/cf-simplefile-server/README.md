![Californium logo](cf_64.png)

# Californium (Cf) - Simple File Server

Enable to use CoAP blockwise [RFC7959 - Block-Wise Transfers in the Constrained Application Protocol](http://tools.ietf.org/html/rfc7959).

## General

Please refer to the eclipse Californium project page for license, build, and install.

## PREPARATION
Generate "Californium.properties" using 

java -jar cf-simplefile-server-2.6.0.jar.

Adjust properties according you setup/environment, at least adjust "MAX_RESOURCE_BODY_SIZE"
to the largest file size you want to support. Make sure, this "Californium.properties" is then used on both sides, server and client.

Create a folder ("data" by default), and place the file(s) in that folder.

## RUN

```sh
java -jar cf-simplefile-server-2.6.0.jar [<file-root-directory> [<coap-root>]]
```

Default for both roots: "data".
So mostly just create a folder "data", add your files to that sub folder and start the jar.

## GET

```sh
URL: coap://<host>/<coap-root>/<file-path>
```

e.g (using `cf-helloworld-client`)

```sh
java -jar cf-helloworld-client-2.6.0.jar coap://localhost/data/file.bin
```

(GET file "file.bin" from file-root-directory).
