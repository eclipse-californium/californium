![Californium logo](../../cf_64.png)

# Californium (Cf) - Cloud Demo Server

## - Reliable - Efficient - Encrypted -

[<img src="./docs/cloudcoap.svg" width="40%" />](./docs/cloudcoap.svg)

Simple cloud demo server for device communication with CoAP/DTLS 1.2 CID . Based on the [Eclipse/Californium CoAP/DTLS 1.2 CID java library](https://github.com/eclipse-californium/californium).

    Kickstart your UDP experience

The server supports DTLS 1.2 CID with **P**re**S**hared**K**ey (similar to username/password), **R**aw**P**ublic**Key** (a public key as certificate without additional information like subject or validity), and x509 certificate authentication for device communication.

Supports resource "devices":

```sh
coap-client -v 6 -m POST -e 'test 1234 50%25' -t 0 -u Client_identity -k secretPSK coaps://<destination>:5684/devices
v:1 t:CON c:POST i:d93a {} [ Uri-Host:aws.coaps.net, Uri-Path:devices, Content-Format:text/plain ] :: 'test 1234 50%'
INFO Identity Hint '' provided
v:1 t:ACK c:2.04 i:d93a {} [ ]
```

**Note:** Please enclose the payload in `'` (single quotes). A "%" in the payload must be escaped with "%25". "-t 0" indicates, that the content is in "text/plain".

```sh
coap-client -v 6 -m GET -u Client_identity -k secretPSK coaps://<destination>:5684/devices/Client_identity
v:1 t:CON c:GET i:7fcf {01} [ Uri-Path:devices, Uri-Path:Client_identity ]
INFO Identity Hint '' provided
v:1 t:ACK c:2.05 i:7fcf {01} [ Content-Format:application/octet-stream ] :: binary data length 13
<<74657374203132333420353025>>
<<t e s t   1 2 3 4   5 0 % >>
INFO *  <source>:60667 <-> <destination>:5684 DTLS: SSL3 alert write:warning:close notify
```

A device may also read the data of other devices.

The server comes with an optional very simple HTTPS server to GET the last CoAP POSTs to resource "devices".

![browser-list](./docs/browser-list.png)

![browser-device](./docs/browser-device.png)

It includes also an optional `diagnose` resource. That records the number of messages and failures.

![browser-diagnose-list](./docs/browser-diagnose-list.png)

![browser-diagnose-page](./docs/browser-diagnose-page.png)

## General Usage

The Cloud Demo Server is available at the eclipse repository and can be downloaded [cf-cloud-demo-server-4.0.0-M3.jar](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-cloud-demo-server/4.0.0-M3/cf-cloud-demo-server-4.0.0-M3.jar).

Start the cf-cloud-demo-server-4.0.0-M3.jar with:

```sh
java -jar cf-cloud-demo-server-4.0.0-M3.jar -h

Usage: CloudDemoServer [-h] [--diagnose] [--wildcard-interface | [[--[no-]
                       loopback] [--[no-]external] [--[no-]ipv4] [--[no-]ipv6]
                       [--interfaces-pattern=<interfacePatterns>[,
                       <interfacePatterns>...]]...]]
                       [--coaps-credentials=<credentials>
                       [--coaps-password64=<password64>]] [--device-file=<file>
                       [--device-file-password64=<password64>]]
                       [--store-file=<file> --store-max-age=<maxAge>
                       [--store-password64=<password64>]] [--provisioning
                       [--replace]] [[--https-port=<port>]
                       --https-credentials=<credentials>
                       [--https-password64=<password64>]]
      --coaps-credentials=<credentials>
                             Folder containing coaps credentials in 'privkey.
                               pem' and 'pubkey.pem'
      --coaps-password64=<password64>
                             Password for device store. Base 64 encoded.
      --device-file=<file>   Filename of device store for coap.
      --device-file-password64=<password64>
                             Password for device store. Base 64 encoded.
      --diagnose             enable 'diagnose'-resource.
  -h, --help                 display a help message
      --https-credentials=<credentials>
                             Folder containing https credentials in 'privkey.
                               pem' and 'fullchain.pem'.
      --https-password64=<password64>
                             Password for https credentials. Base 64 encoded.
      --https-port=<port>    Port of https service. Default: 8080
      --interfaces-pattern=<interfacePatterns>[,<interfacePatterns>...]
                             interface regex patterns for coap endpoints.
      --[no-]external        enable coap endpoints on external network.
      --[no-]ipv4            enable coap endpoints for ipv4.
      --[no-]ipv6            enable coap endpoints for ipv6.
      --[no-]loopback        enable coap endpoints on loopback network.
      --provisioning         enable 'prov'-resource for auto-provisioning.
      --replace              replaces previous device credentials entries with
                               new entries. For use during development. Don't
                               use it for production!
      --store-file=<file>    file-store for dtls state.
      --store-max-age=<maxAge>
                             maximum age of connections in hours to store dtls
                               state.
      --store-password64=<password64>
                             password to store dtls state. Base 64 encoded.
      --wildcard-interface   Use local wildcard-address for coap endpoints.
                               Default mode.

Examples:
  DemoServer --no-loopback --device-file devices.txt
    (DemoServer listening only on external network interfaces.)

  DemoServer --store-file dtls.bin --store-max-age 168 \
                --store-password64 ZVhiRW5pdkx1RUs2dmVoZg== \
                --device-file devices.txt

    (DemoServer with device credentials from file and dtls-graceful restart.
     Devices/sessions with no exchange for more then a week (168 hours) are
     skipped when saving.)

  DemoServer --store-file dtls.bin --store-max-age 168 \
                --store-password64 ZVhiRW5pdkx1RUs2dmVoZg== \
                --device-file devices.txt --https-credenitals .

    (DemoServer with device credentials from file and dtls-graceful restart.
     A simple HTTP server is started at port 8080 using the x509 certificates
     from the current directory (certificate is required to be provided).
     Devices/sessions with no exchange for more then a week (168 hours) are
     skipped when saving.)
```

to see the set of options and arguments.

When the server is started the first time, it creates the "CaliforniumCloudDemo3.properties" file. This contains the settings, which may be adjusted by editing this file.

```
# Californium CoAP Properties file for S3 Proxy Server
# Fri Apr 05 18:16:24 CEST 2024
#
# Cache maximum devices.
# Default: 5000
CACHE_MAX_DEVICES=5000
# Threshold for stale devices. Devices will only get removed for new
# ones, if at least for that threshold no messages are exchanged with
# that device.
# Default: 1[d]
CACHE_STALE_DEVICE_THRESHOLD=1[d]
# Reload device credentials interval. 0 to load credentials only on
# startup.
# Default: 1[min]
DEVICE_CREDENTIALS_RELOAD_INTERVAL=30[s]
# Reload HTTPS credentials interval. 0 to load credentials only on startup.
# Default: 30[min]
HTTPS_CREDENTIALS_RELOAD_INTERVAL=30[min]
...
```

**Note:** to use encrypted device files, please use the [cf-encrypt](../../cf-utils/cf-encrypt/README.md) utility. Same applies for the https and coaps credentials, encrypted PKCS #8 is not supported, you must use PKCS #8 without encryption and apply that `cf-encrypt` utility.

## Device Credentials

In order to authenticate the devices, PSK (Pre-Shared-Key, [RFC4279](https://www.rfc-editor.org/rfc/rfc4279)), RPK (Raw-Public-Key, [RFC7250](https://www.rfc-editor.org/rfc/rfc7250)),or x509 ([RFC5280](https://www.rfc-editor.org/rfc/rfc5280)) are supported. The device credentials are stored in a [text-file, e.g. demo-devices.txt](./service/demo-devices.txt) in the local file system of the cloud VM.

```
# Device store for Cloud Demo

Demo.10034780012=Thing
.label=My Demo Weatherstation
# default openssl PSK credentials
.psk='Client_identity',c2VjcmV0UFNL
# Californium demo-client RPK certificate
.rpk=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQxYO5/M5ie6+3QPOaAy5MD6CkFILZwIb2rOBCX/EWPaocX1H+eynUnaEEbmqxeN6rnI/pH19j4PtsegfHLrzzQ==

Demo.10560970055=Thing
.psk='cali.0012345','secretPSK'

# x509 CA (trust root)
ca.1=Admin
.type=ca
.x509=
-----BEGIN CERTIFICATE-----
MIIB6jCCAZCgAwIBAgIIVcDMBTw+KzcwCgYIKoZIzj0EAwIwXDEQMA4GA1UEAxMH
Y2Ytcm9vdDEUMBIGA1UECxMLQ2FsaWZvcm5pdW0xFDASBgNVBAoTC0VjbGlwc2Ug
SW9UMQ8wDQYDVQQHEwZPdHRhd2ExCzAJBgNVBAYTAkNBMB4XDTI0MTEwNDE4MTUz
MFoXDTI2MTEwNDE4MTUzMFowXDEQMA4GA1UEAxMHY2Ytcm9vdDEUMBIGA1UECxML
Q2FsaWZvcm5pdW0xFDASBgNVBAoTC0VjbGlwc2UgSW9UMQ8wDQYDVQQHEwZPdHRh
d2ExCzAJBgNVBAYTAkNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzx3KwWUN
2s7ad0CComh/dfNEg64Z7THbM64Bm8BOgFBN9284SSrboMvdAIOQamDP/aAmhFV3
6Qg/SF1A5qTW9qM8MDowHQYDVR0OBBYEFBifxGwtiNzNWfvoU9IdZYrqJqp3MAsG
A1UdDwQEAwIBBjAMBgNVHRMEBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIGU7bo83
m29D12Tf2BA9DVC+48dpmib6FGwoxwIGyKGaAiEA0KXJd7IGpmcdxiroGJ+89+/2
TZIohp/YlALdHH1U/nU=
-----END CERTIFICATE-----

# x509 device certificate, signed by Ca
Demo.40145780125=Thing
.label=Door
.x509=
-----BEGIN CERTIFICATE-----
MIICAjCCAaigAwIBAgIJAJvzugZ7RkwVMAoGCCqGSM49BAMCMFwxEDAOBgNVBAMT
B2NmLXJvb3QxFDASBgNVBAsTC0NhbGlmb3JuaXVtMRQwEgYDVQQKEwtFY2xpcHNl
IElvVDEPMA0GA1UEBxMGT3R0YXdhMQswCQYDVQQGEwJDQTAeFw0yNDExMDcxNTA5
MzVaFw0yNjExMDcxNTA5MzVaMGAxFDASBgNVBAMTC2NmLWNsaWVudC0yMRQwEgYD
VQQLEwtDYWxpZm9ybml1bTEUMBIGA1UEChMLRWNsaXBzZSBJb1QxDzANBgNVBAcT
Bk90dGF3YTELMAkGA1UEBhMCQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATa
v2cItqEoanxb1UduhvKR+dlbkr0lsbR/ql01UPuAa2ONNt9uIl9FCXoF3V/VzE3O
xW5+YTUraJ/CcuARZC5Mo08wTTAdBgNVHQ4EFgQU0d8npcBVyIxSwE9hPFTJ7qmZ
04owCwYDVR0PBAQDAgeAMB8GA1UdIwQYMBaAFBifxGwtiNzNWfvoU9IdZYrqJqp3
MAoGCCqGSM49BAMCA0gAMEUCIQC5F+tgTY5IzmbjlXqQE6ha/hFHE981mo0pSAzv
NdTutwIgS0YrTmYDan4J8Z+svEG89HbLk2QlY2aGrzyjce7faSk=
-----END CERTIFICATE-----

```

The format starts with a device definition, using the device `name`, followed by a '=' and the `group` the device belongs to. Each device belongs to one group and you may use a couple of groups to partition your devices. Currently the groups are only used by the [Californium (Cf) - Cloud CoAP-S3-Proxy Server](../cf-s3-proxy-server) to select the devices shown initial after login.

It is recommended to use a long term stable and unique values for the `name`. Technical IDs are candidates for that, but they are bad for humans as identifiers. Therefore you may provide a human recognizable `label` to mitigate that.

**Note:** the server's device credentials file is read using UTF-8 encoding, '=' are not supported for device names. Lines starting with '#' are skipped as comment, therefore a device name must not start with a '#'. Empty lines are also skipped.

The cloud demo server checks frequently, if the file has changed and automatically reloads the device credentials.

Devices already connected with removed or banned credentials are kept connected. The requests of such a device will be respond with 4.03 (FORBIDDEN). On the next handshake these device will fail to communicate with the cloud demo server.

### Device Credentials - PSK

PSK credentials are provided with `[<name>].psk=<psk-identity>,<psk-secret>`. If the `name` is skipped, the name of the last device definition is used. If the `name` is provided, then it must match the name of the last device definition. The `psk-identity` is provided in UTF-8 and the `psk-secret` in base64. The `psk-identity` must be unique for each device of the system. If hexadecimal should be used, then provide it with preceding ":0x".

```
# default openssl PSK credentials
.psk='Client_identity',:0x73656372657450534B
```

### Device Credentials - RPK

RPK credentials are provided similar with `[<name>].rpk=<public-key>`. The `public-key` is in base64 or with ":0x" in hexadecimal.

```
# Californium demo-client RPK certificate
.rpk=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQxYO5/M5ie6+3QPOaAy5MD6CkFILZwIb2rOBCX/EWPaocX1H+eynUnaEEbmqxeN6rnI/pH19j4PtsegfHLrzzQ==
```

That `public-key` must also be unique for each device, which will be natural, if a fresh key-pair is generated for each device. How that fresh device `key-pair` is generated depends on the device. If that supports also to import a device `key-pair`, then you may use `openssl` to create a `key-pair`.

```sh
openssl ecparam -genkey -name prime256v1 -noout -out device1-key.pem
```

or

```sh
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out device1-key.pem
```

(The later command "supersedes" the first according the openssl documentation. The PEM created by that commands contains both, the private and the public key.)

To add this device to the credentials, export the `public key` with

```sh
openssl pkey -pubout -in device1-key.pem

-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENTGXGkhc7gL614R4HBOkXoESM98Y
IXP3yts4VG7wpRlsIxYFFXVez3I3VE7oGaOpLlAMMhFa4Myq/4OIRMvauQ==
-----END PUBLIC KEY-----
```

and copy the base 64 part of the result to the credentials file (one line, no "----" lines).

```
Demo.device1=Thing
.rpk=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENTGXGkhc7gL614R4HBOkXoESM98YIXP3yts4VG7wpRlsIxYFFXVez3I3VE7oGaOpLlAMMhFa4Myq/4OIRMvauQ==
```

The device will need the `private key` of this pair. How that is done, depends on the device. If that requires the `private key` in base64 pem, then export it with:

```sh
openssl ec -no_public -in device1-key.pem

read EC key
writing EC key
-----BEGIN EC PRIVATE KEY-----
MDECAQEEIMjsiXRzR3OYtELs+9tWYHB4/nT9x3LAXFzA8ezR8iVLoAoGCCqGSM49
AwEH
-----END EC PRIVATE KEY-----
```

and provide the base 64 part to the device.

RPK requires the server also to authenticate itself using a `key-pair`. To load the server's `key-pair` use `--coaps-credentials <directory>`. The directory must contain a `privkey.pem`, and, if that doesn't contain the public key as well, a  `publickey.pem`.

You may either provide that server's `key pair` on your own or create a new one using `openssl` with:

```sh
openssl ecparam -genkey -name prime256v1 -noout -out privkey.pem
```

or

```sh
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out privkey.pem
```

as already introduced above for creating device key-pairs.

(As already mentioned, the PEM created by that commands contains both, the private and the public key. Therefore the server needs only this one. Other formats or tools may have other results and you may need then two files, one `privkey.pem` and one `publickey.pem`.)

The `public key` of that server pair must be provided to devices, which then use that to trust this server. How the `public key` is provided depends on the device. If that requires the `public key` in base64 pem, then export it as show above for the device's `key-pair`.

Otherwise follow the instruction of the device how to supply the server `public key`. And don't mix it up with x509, RPK doesn't match for that.

### Device Credentials - x509

**Note:** using x509 comes usually with a quite high level of complexity and possibilities. That isn't covered here, only the basics for adding x509 certificates are explained.

X509 certificates are provided with `[<name>].x509=` and the certificate in base 64 from the ".pem".

```
# x509 device certificate, signed by Ca
Demo.40145780125=Thing
.label=Door
.x509=
-----BEGIN CERTIFICATE-----
MIICAjCCAaigAwIBAgIJAJvzugZ7RkwVMAoGCCqGSM49BAMCMFwxEDAOBgNVBAMT
B2NmLXJvb3QxFDASBgNVBAsTC0NhbGlmb3JuaXVtMRQwEgYDVQQKEwtFY2xpcHNl
IElvVDEPMA0GA1UEBxMGT3R0YXdhMQswCQYDVQQGEwJDQTAeFw0yNDExMDcxNTA5
MzVaFw0yNjExMDcxNTA5MzVaMGAxFDASBgNVBAMTC2NmLWNsaWVudC0yMRQwEgYD
VQQLEwtDYWxpZm9ybml1bTEUMBIGA1UEChMLRWNsaXBzZSBJb1QxDzANBgNVBAcT
Bk90dGF3YTELMAkGA1UEBhMCQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATa
v2cItqEoanxb1UduhvKR+dlbkr0lsbR/ql01UPuAa2ONNt9uIl9FCXoF3V/VzE3O
xW5+YTUraJ/CcuARZC5Mo08wTTAdBgNVHQ4EFgQU0d8npcBVyIxSwE9hPFTJ7qmZ
04owCwYDVR0PBAQDAgeAMB8GA1UdIwQYMBaAFBifxGwtiNzNWfvoU9IdZYrqJqp3
MAoGCCqGSM49BAMCA0gAMEUCIQC5F+tgTY5IzmbjlXqQE6ha/hFHE981mo0pSAzv
NdTutwIgS0YrTmYDan4J8Z+svEG89HbLk2QlY2aGrzyjce7faSk=
-----END CERTIFICATE-----
```

X509 device certificates requires to add a certificate of a **C**ertificate **A**uthority as well. Use `[<name>].type=ca` to add that.

To generate x509 certificates you may use the java `keytool` as show in [create-keystores.sh](./src/main/resources/create-keystores.sh).

To block/ban a device or CA `[<name>].ban=1` is used. Banning a CA will also ban all devices with that CA as trust root.

## Device Credentials - Auto-Provisioning

In order to provision devices efficiently, an auto-provisioning function can be used. This requires to enable `auto-provisioning` via the cli option (`--auto-provisioning`) and to add `auto-provisioning-credentials` to the device store.

```
Provisioning1=Admin
.rpk=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENTGXGkhc7gL614R4HBOkXoESM98YIXP3yts4VG7wpRlsIxYFFXVez3I3VE7oGaOpLlAMMhFa4Myq/4OIRMvauQ==
.type=prov
```

That's done by the entry above. It contains a name (`Provisioning1`), the `public key` from the `auto-provisioning key-pair` and the type `.type=prov`. For now, only RPK is supported for authentication `auto-provisioning`. Such a `auto-provisioning key-pair` is a **shared** device `key-pair`. A bulk of device may use the same to execute the provisioning. It's only supported to be used for that `auto-provisioning` and in a sequential mode, device by device. Sending other data will not work, sending parallel request with the same `auto-provisioning key-pair` may fail. You may use the approach using openssl described [above](#device-credentials) to create such a `auto-provisioning key-pair`.

For production it's only successful, if the `device-id` is not already used. For development, this may be overwritten, if `--replace` is passed as cli option. On success, the entry is added to the device credentials.

```
...
# added 2024-08-11T07:00:19Z by Provisioning1
device-id=Thing
.rpk=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEe7jf4/mFVId9GnUfFdV1XQVUAn4fAKsctXYfLnrcvKMXAPAKe6mLPNMNxXf/+TsDQDXEcamWAcjDUFVc/9pIeQ==
.sig=BAMARzBFAiEAkL9amzTcqBrovw3EPeUJ+iB/NhiEhgS603VBGDx6UUMCIDNfKVwOG7aCQVnsL7mDqgQZhXW7XrCMEKp0hAk7wGac
```

If the device uses a x509 certificate `auto-provisioning` uses the `CA` credentials to authorize the provisioning. The device certificate is then extracted during the handshake and only `<name>=<group>` must then be sent in the provisioning request.

## DTLS Graceful Restart

The cloud demo server supports to save the DTLS connection state and load it again. With this feature, it's possible to restart the server without losing the DTLS connection state. Provide the arguments `--store-file` (filename to save and load the DTLS connection state), `--store-password64` (base64 encoded password to save and load the DTLS connection state), and `--store-max-age` (maximum age of connections to be stored. Value in hours) are provided.

Stop the server and start it again using the same `--store-file` and `--store-password64` as before and also provide the `--store-max-age`.

**Note:** if it takes too long between stopping and restart, the clients will detect a timeout and may trigger new handshakes. So just pause a small couple of seconds!

**Note:** only the DTLS state is persisted. To use this feature, the client is intended to use mainly CON request and the server then uses piggybacked responses. Neither DTLS handshakes, separate responses, observe/notifies, nor blockwise transfers are supported to span a restart.

## DTLS Graceful Restart - Server Updates

Save and (re-)load the DTLS state makes a server update also seamless for the devices. Stop the old and start the new server jar usually takes only a few seconds and the most devices will not be affected at all. Only a few may send messages during the restart and without response they will just resend it short afterwards again. And at that time, the server is usually running again.

There is small pitfall with this approach: if you write the new jar in place over the currently executed one, then the shutdown may fail with errors caused by that changed jar. Therefore a second jar is used to place the update and on restart that update jar is copied to the executed on. The [Systemd Service](#systemd-service) described below handles that by:

```
ExecStartPre=/bin/cp -u cf-cloud-demo-server-update.jar ${JAR}
```

## Web HTTPS forwarding

The server runs as user "cali" and therefore requires to forward TCP:443 to a user service port (8080). Copy [iptables service](./service/iptables.service) into `/etc/systemd/system` and [iptables-firewall.sh](./service/iptables-firewall.sh) into `sbin` and make that file executable.

## HTTPS x509 certificate

The https server requires x509 certificate credentials. You may setup a own CA, use a public one, or the CA provided by your cloud-provider.

Regardless of a private, public or cloud provider's CA, the result should be a private key and a related and signed x509 certificate chain. Save both in a directory using the names `privkey.pem` and `fullchain.pem` and pass that directory using `--https-credentials <dir>`. Ensure, the user "cali" or group "cali" has read access to it. The server first reads the `fullchain.pem`. If that also contains the private key, `privkey.pem` is not used.

Please consult the CA's documentation how to create these credentials.

### HTTPS x509 certificate - Let's encrypt

One public CA is [Let's Encrypt](https://letsencrypt.org/). 

If you want to use it, install [certbot](https://certbot.eff.org/instructions?ws=other&os=ubuntufocal) or a similar tool and request a x509 http server certificate for your DNS-domain. Raw ip-addresses are not supported by let's encrypt. Prior to requesting a certificate, you need to ensure, that you possess/control the DNS-domain and that this DNS-domain points to the right ip-address of the cloud-vm. Consult the documentation of your domain provider how to achieve that.

```sh
certbot certonly --standalone --key-type ecdsa --elliptic-curve secp256r1 -d <dns-domain>
```

You will be asked about an e-mail address and to accept the [Let's Encrypt Service Agreement](https://letsencrypt.org/documents/LE-SA-v1.3-September-21-2022.pdf).

The received credentials are stored in `/etc/letsencrypt/archive/<dns-domain>/` and stable links to read them are available in `/etc/letsencrypt/live/<dns-domain>`. Pass that `--https-credentials=/etc/letsencrypt/live/<dns-domain>` to the cloud demo server.

Let's encrypt assumes by default the root user reads the credentials. The cloud demo server uses the limited user "cali". In order to read the credentials by that limited user "cali", the access rights on the file-system must be adjusted.

Adjust permission to grant others read-access to the directories "live" and "archive":

```sh
chmod go+rx /etc/letsencrypt/live
chmod go+rx /etc/letsencrypt/archive
```

And in order to read the private key, you need to add adjust the permission of the file as well. Therefore set group to "cali" and adjust permission to grant the group read-access:

```sh
chown root:cali /etc/letsencrypt/archive/<dns-domain>/privkey1.pem
chmod g+r /etc/letsencrypt/archive/<dns-domain>/privkey1.pem
```

(**Note:** in "archive" the files are numbered, in "live" are links to the most recent file are without numbers. See [letsencrypt.sh](./service/letsencrypt.sh).)

These permissions are kept, if the credentials are renewed. `Certbot` does this renewal automatically. The https server also checks for new certificates and restarts automatically, when new certificates are detected.

For more details about `certbot, see instructions at [certbot](https://eff-certbot.readthedocs.io/en/stable/using.html#where-are-my-certificates).

## fail2ban

To ban some host from continue sending malicious messages, Californium support to write the source ip-addresses of malicious messages into a special log file.
The cloud demo server uses logback for logging, and configures therefore a file-appender and configures the logger "org.eclipse.californium.ban" to use that.

```
	<appender name="BAN_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
		<file>logs/ban.log</file>
		<rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
			<!-- roll-over monthly, or if filesize exceeds -->
			<fileNamePattern>logs/ban-%d{yyyy-MM}.%i.log</fileNamePattern>
			<!-- each file should be at most 1MB, keep 10 files worth of history, but at most 10MB -->
			<maxFileSize>1MB</maxFileSize>
			<maxHistory>10</maxHistory>
			<totalSizeCap>10MB</totalSizeCap>
		</rollingPolicy>

		<encoder>
			<!-- use tab to separate timestamp from message -->
			<pattern>[%date{yyyy-MM-dd HH:mm:ss}]\t%msg%n</pattern>
		</encoder>
	</appender>

	<logger name="org.eclipse.californium.ban" level="INFO" additivity="false">
		<appender-ref ref="BAN_FILE" />
	</logger>

```

The content of that file is:

```
[2023-05-12 07:10:11]	coaps Option Content-Format value of 3 bytes must be in range of [0-2] bytes. 5203ABDA15E9B763 DTLS Ban:??.??.??.??
[2023-05-12 07:57:50]	https: GET /actuator/gateway/routes HTTP/1.1 HTTPS Ban: ??.??.??.??
[2023-05-12 08:26:38]	https: GET /robots.txt HTTP/1.1 HTTPS Ban: ??.??.??.??
```

### fail2ban - installation

```
sudo apt install fail2ban
```

To configure fail2ban, define filters, e.g.:

```
[INCLUDES]

before = common.conf

[Definition]

failregex = DTLS\s+Ban:\s+<HOST>$
```

and copy [calidtls.conf](./service/fail2ban/calidtls.conf) into folder "/etc/fail2ban/filter.d". That selects the `<HOST>` after the tags "DTLS" and "Ban:".

Additional [calihttps.conf](./service/fail2ban/calihttps.conf) filters for "HTTPS" and "Ban:", and [calilogin.conf](./service/fail2ban/calilogin.conf) filters for "LOGIN" and "Ban:". These filter must additionally be copied into folder "/etc/fail2ban/filter.d".

The different filters enables to define different jail rules for violations, e.g.:

```
[DEFAULT]
bantime  = 1800
findtime = 300

[cali-dtls]
enabled  = true
port     = 5684
protocol = udp
filter = calidtls
logpath  = /home/cali/logs/ban.log

# https: use nat destination port 8080!

[cali-https]
enabled  = true
port     = 8080
protocol = tcp
filter = calihttps
logpath  = /home/cali/logs/ban.log

[cali-login]
enabled  = true
port     = 8080
protocol = tcp
filter = calilogin
logpath  = /home/cali/logs/ban.log
bantime  = 300
findtime = 150
```

and copy [cali2fail.conf](./service/fail2ban/cali2fail.conf) into folder "/etc/fail2ban/jail.d". That applies the before defined filter to the "ban.log" and "jails" `<HOST>`. DTLS and HTTPS violations will be banned for 30 minutes, if 3 violations are detected within 5 minutes. LOGIN violations will be banned for 5 minutes, if 3 violations are detected within 2 minutes and 30 seconds.

To check the jail, use

```
fail2ban-client status cali-https
Status for the jail: cali-https
|- Filter
|  |- Currently failed:	2
|  |- Total failed:	1000
|  `- File list:	/home/cali/logs/ban.log
`- Actions
   |- Currently banned:	0
   |- Total banned:	23
   `- Banned IP list:	
```

## Systemd Service

**Note:** The installation contains "secrets", e.g. to store the DTLS state or to read the device credentials. Therefore a dedicated cloud-VM must be used and the access to that cloud-VM must be protected! This basic/simple setup also uses the "root" user. Please replace/add a different user according your security policy.

This instructions assumes to be already common with tools used around "headless compute units" and "cloud computing". It does not contain the basic instruction for using them. For some more details, see the script's [README](./service/cloud-installs/README.md)

The Cloud Demo Server is available at the eclipse repository and can be downloaded [cf-cloud-demo-server-3.13.0.jar](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-cloud-demo-server/3.13.0/cf-cloud-demo-server-3.13.0.jar).

The server runs as [systemd service](./service/cali.service). It may be installed either manually or using the [installation script](./service/cloud-installs/deploy-dev.sh). In order to be able to apply updates to the server software, the `systemd service` uses a second jar with "update" in its name, that will be copied to the executed jar before starting the execution.

Manual installation follows the [cf-unix-setup](../cf-unix-setup). It requires also to add the [Web HTTPS forwarding](#web-https-forwarding) and to create the https x509 credentials as [described above](#https-x509-certificate). That approach doesn't require specific scripts and should fit for any cloud, which supports "compute instance" with UDP support. It will come with costs!

The alternative is to use the [installation script](./service/cloud-installs/deploy-dev.sh), which supports the [ExoScale](https://www.exoscale.com/), [DigitalOcean](https://cloud.digitalocean.com), and [AWS](https://aws.amazon.com). It requires an account at that provider and to download and install the provider's CLI tools. It also comes with costs! See [ExoScale Script](./service/cloud-installs/provider-exo.sh), [DigitalOcean Script](./service/cloud-installs/provider-do.sh) and [AWS Script](./service/cloud-installs/provider-aws.sh) for more details and requirements.

The install script also requires to build the Cloud Demo Server locally, please follow [Build using Maven](../../README.md#build-using-maven).

The script provides jobs to "create" (create cloud VM/EC2 instance), "install" (install cloud demo server service from local sources and builds, along with fail2ban, web-https-forwarding and preparation for `certbot`), "update" (Update cloud demo server service from local sources and builds), "login" (ssh login into cloud-VM), and "delete" (delete cloud-VM). It is currently configured to use a [Ubuntu 22.04 LTS Server](https://ubuntu.com/download/server) image, but you may adapt that in the scripts.

Usage:

```sh
./deploy-dev.sh exo create install
```

Creates a ExoScale cloud-VM and installs the cloud-demo-server including generating a key-pair for RPK. On finish, the file [permissions](./service/permissions.sh) are adjusted and the installation is completed by a reboot.

Initially the default openssl PSK device credentials are provided (identity: Client_identity, shared key: secretPSK). That is intended to be replaced by you soon by editing the "/home/cali/demo-devices.txt" file.

To enable the simple web read access, a x509 certificate is required. As mentioned [above](#https-x509-certificate---lets-encrypt), this requires to redirect the intended DNS-domain to the ip-address of the create cloud VM. The ip-address is shown at the end of the installation:

```sh
...
Reboot cloud VM.
use: ssh root@?1.?2.??7.8? to login!
```

Please consult your DNS provider how to redirect your DNS-domain to that ip-address.

After redirecting the DNS-domain, login to the cloud VM.

```sh
ssh root@?1.?2.??7.8?
```

and request a certificate with the script provided during the installation.

```sh
./letsencrypt.sh <dns-domain>
```

The script adjusts the required permission on the file-system and also adapts the [/etc/systemd/system/cali.service](./service/cali.service) file on the cloud-VM and adding `--https-credentials` 

```
Environment="HTTPS_CERT_ARGS=--https-credentials=/etc/letsencrypt/live/<dns-domain>"
```

Finally it restarts the service

That's it for the web application. After a couple of seconds try to test the coaps-server using:

```sh
coap-client -v 6 -m POST -e 'test 1234 50%25' -t 0 -u Client_identity -k secretPSK coaps://<dns-domain>:5684/devices
```

and the https-server using a web-browser and `https://<dns-domain>`. If both test are succeed, then your cloud demo server is installed well.
