![Californium logo](../../cf_64.png)

# Californium - Example Cross Proxy 2

The ExampleCrossProxy2 demonstrates the functions of the [californium-proxy2](../../californium-proxy2) library. See [californium-proxy2 README.md](../../californium-proxy2/README.md) for more details.

## Usage

Start the proxy:
 
```sh
java -jar cf-proxy2-<version>.jar ExampleCrossProxy2 coap http
```

This starts the example cross-proxy and a co-located coap- and http-destination-server.

Start a example coap-client (same host as proxy):

```sh
java -jar cf-proxy2-<version>.jar ExampleProxy2CoapClient
```

Start a example http-client (same host as proxy):

```sh
java -jar cf-proxy2-<version>.jar ExampleProxy2HttpClient
```

To test other setups requires to edit the examples and build them on your own.

## Usage with outgoing coaps

Start the proxy:
 
```sh
java -jar cf-proxy2-<version>.jar ExampleSecureProxy2 coaps
```

This starts the example cross-proxy and a co-located coaps-destination-server.

Start a example coaps-client (same host as proxy):

```sh
java -jar cf-proxy2-<version>.jar ExampleSecureProxy2CoapClient
```

## Expected Output Of Example Clients

```sh
=== GET http://localhost:8080 ===
HTTP/1.1 200 OK
Etag: 8b86b935
Date: So., 20 Okt. 2024 15:20:27 GMT
Content-Length: 36
Content-Type: text/plain; charset=UTF-8
Connection: keep-alive
Californium Http Proxy on port 8080.
=== GET http://localhost:8080/proxy/coap://localhost:5685/coap-target ===
HTTP/1.1 200 OK
Etag: 4D4B9060
Cache-Control: max-age=15
content-type: text/plain; charset=ISO-8859-1
Date: So., 20 Okt. 2024 15:20:27 GMT
Content-Length: 49
Connection: keep-alive
Hi! I am the coap server on port 5685. Request 1.
=== GET http://localhost:8080/proxy/coap:%2f%2flocalhost:5685/coap-target ===
HTTP/1.1 200 OK
Etag: 4D4B9060
Cache-Control: max-age=15
content-type: text/plain; charset=ISO-8859-1
Date: So., 20 Okt. 2024 15:20:27 GMT
Content-Length: 49
Connection: keep-alive
Hi! I am the coap server on port 5685. Request 1.
=== GET http://localhost:8080/proxy?target_uri=coap://localhost:5685/coap-target ===
HTTP/1.1 200 OK
Etag: 4D4B9060
Cache-Control: max-age=15
content-type: text/plain; charset=ISO-8859-1
Date: So., 20 Okt. 2024 15:20:27 GMT
Content-Length: 49
Connection: keep-alive
Hi! I am the coap server on port 5685. Request 1.
=== GET http://localhost:8080/proxy/http:%2f%2flocalhost:8000/http-target ===
HTTP/1.1 200 OK
Etag: 6362333239316537
Cache-Control: max-age=60
content-type: text/plain; charset=ISO-8859-1
Date: So., 20 Okt. 2024 15:20:27 GMT
Content-Length: 49
Connection: keep-alive
Hi! I am the Http Server on port 8000. Request 1.
=== GET http://localhost:8080/local/target ===
HTTP/1.1 200 OK
Cache-Control: no-cache
content-type: text/plain; charset=ISO-8859-1
Date: So., 20 Okt. 2024 15:20:27 GMT
Content-Length: 55
Connection: keep-alive
Hi! I am the local coap server on port 5683. Request 1.
=== GET http://localhost:5685/coap-target/coap: ===
HTTP/1.1 200 OK
Etag: 4D4B9060
Cache-Control: max-age=15
content-type: text/plain; charset=ISO-8859-1
Date: So., 20 Okt. 2024 15:20:27 GMT
Content-Length: 49
Hi! I am the coap server on port 5685. Request 1.
=== GET http://localhost:5685/coap-empty/coap: ===
HTTP/1.1 204 No Content
cache-control: max-age=60
Date: So., 20 Okt. 2024 15:20:27 GMT
<empty>
=== GET http://californium.eclipseprojects.io:5683/test/coap: ===
HTTP/1.1 200 OK
Cache-Control: max-age=30
content-type: text/plain; charset=ISO-8859-1
Date: So., 20 Okt. 2024 15:20:27 GMT
Content-Length: 61
Type: 0 (CON)
Code: 1 (GET)
MID: 1658
Token: F08EF92E7C93E122
=== PUT http://californium.eclipseprojects.io:5683/test/coap: === (no payload)
HTTP/1.1 204 No Content
Date: So., 20 Okt. 2024 15:20:27 GMT
<empty>
=== PUT http://californium.eclipseprojects.io:5683/test/coap: === ''
HTTP/1.1 204 No Content
Date: So., 20 Okt. 2024 15:20:27 GMT
<empty>
=== PUT http://californium.eclipseprojects.io:5683/test/coap: === '1234'
HTTP/1.1 204 No Content
Date: So., 20 Okt. 2024 15:20:27 GMT
<empty>
=== POST http://californium.eclipseprojects.io:5683/echo/coap:?id=me&keep === ''
HTTP/1.1 204 No Content
Date: So., 20 Okt. 2024 15:20:27 GMT
<empty>
=== GET http://californium.eclipseprojects.io:5683/echo/me/coap: ===
HTTP/1.1 204 No Content
cache-control: max-age=60
Date: So., 20 Okt. 2024 15:20:27 GMT
<empty>
=== POST http://californium.eclipseprojects.io:5683/echo/coap:?id=me&keep === '123'
HTTP/1.1 200 OK
content-type: text/plain; charset=ISO-8859-1
Date: So., 20 Okt. 2024 15:20:27 GMT
Content-Length: 3
123
=== GET http://californium.eclipseprojects.io:5683/echo/me/coap: ===
HTTP/1.1 204 No Content
Cache-Control: max-age=60
Date: So., 20 Okt. 2024 15:20:27 GMT
<empty>
```

```sh
java -jar target/cf-proxy2-4.0.0-SNAPSHOT.jar ExampleProxy2CoapClient
Proxy-URI GET: http://localhost:8000/http-target
etag: '9b1fafc1', 0x3962316661666331
2.05/CONTENT --- Hi! I am the Http Server on port 8000. Request 25.
Proxy-URI GET: coap://localhost:5685/coap-target
etag: '\&|i', 0x5C267C69
2.05/CONTENT --- Hi! I am the coap server on port 5685. Request 13.
Proxy-Scheme GET: http: coap://localhost:8000/http-target
etag: '9b1fafe0', 0x3962316661666530
2.05/CONTENT --- Hi! I am the Http Server on port 8000. Request 26.
Proxy GET: coap://localhost:5685/coap-target
etag: '\&|i', 0x5C267C69
2.05/CONTENT --- Hi! I am the coap server on port 5685. Request 13.
Proxy GET: coap://127.0.0.1:5685/coap-target
etag: 0x5C267C88
2.05/CONTENT --- Hi! I am the coap server on port 5685. Request 14.
Proxy GET: coap://127.0.0.1:5685/coap-target
etag: 0x5C267C88
2.05/CONTENT --- Hi! I am the coap server on port 5685. Request 14.
Proxy-URI GET: http://user@localhost:8000/http-target => 4.00/BAD_REQUEST
   => 'Request URI authority contains deprecated userinfo component'
4.00/BAD_REQUEST --- Request URI authority contains deprecated userinfo component
Proxy GET: coap://localhost/coap-target => 4.04/NOT_FOUND
4.04/NOT_FOUND
Reverse-Proxy GET: coap://localhost/targets/destination1
etag: '\&|i', 0x5C267C69
2.05/CONTENT --- Hi! I am the coap server on port 5685. Request 13.
Reverse-Proxy GET: coap://localhost/targets/destination2
etag: '9b1fafff', 0x3962316661666666
2.05/CONTENT --- Hi! I am the Http Server on port 8000. Request 27.
CoapClient using Proxy:
CoapClient Proxy POST: coap://localhost:8000/http-target
etag: '9b1fb01e', 0x3962316662303165
2.04/CHANGED --- Hi! I am the Http Server on port 8000. Request 28.
CoapClient Proxy POST: coap://localhost:8000/http-target
etag: 0x0BD1844E
2.05/CONTENT --- Hi, coap-client! I am the coap server on port 5685. Request 15.
CoapClient Proxy POST: coap://localhost:8000/http-target
etag: '9b1fb03d', 0x3962316662303364
2.04/CHANGED --- Hi! I am the Http Server on port 8000. Request 29.
CoapClient Proxy POST: coap://localhost:8000/http-target
etag: '9b1fb2e7', 0x3962316662326537
2.04/CHANGED --- Hi! I am the Http Server on port 8000. Request 30.
CoapClient Proxy GET: coap://localhost:8000/http-target
etag: '9b1fb306', 0x3962316662333036
2.05/CONTENT --- Hi! I am the Http Server on port 8000. Request 31.
CoapClient Proxy GET: coap://localhost:8000/http-target
2.05/CONTENT

```