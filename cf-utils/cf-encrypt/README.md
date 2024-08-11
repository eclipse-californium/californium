![Californium logo](../../cf_64.png)

# File encryption and key extraction

This utility app provides encryption and decryption of configuration files as well as starting with version 4.0 extracting key data from .pem files in order to pass them to the device clients and converting .pem files into C-headers.

# Download

[Eclipse Release Repository (3.12)](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-encrypt/3.12.0/cf-encrypt-3.12.0.jar)

#Usage

Usage:

```sh
java -jar cf-encrypt-<version>.jar file
java -jar cf-encrypt-<version>.jar key
java -jar cf-encrypt-<version>.jar toc
```

## Usage for file encryption:

```sh
java -jar cf-encrypt-<version>.jar file --password64 <password-base64>
        [(--encrypt [--cipher <cipher>]|--decrypt)] [--out <file>] [--in] <file>
```

## Arguments for file encryption:

       --password64   : password base 64 encoded
       --encrypt      : encrypt file. Default mode.
         --cipher     : cipher to encrypt file. Default "AES/GCM/128" or 
                        "AES/CBC/128", if GCM is not supported by the JCE.
                        ("AES/GCM/128" is supported by this JCE.)
       --decrypt      : decrypt file
       --out          : output file name. Default replaces input file.
       --in           : input file name.

## File encryption for configuration files with credentials

In order slightly better protect credentials in configuration files, this tool encrypts such files.

The format is quite simple:

- 2 bytes cipher code
- 1 bytes nonce length
- n bytes nonce
- p bytes encrypted payload
- m bytes mac (depending on the selected cipher)

## File encryption examples

Encrypt file:

```sh
java -jar cf-encrypt-<version>.jar file --password64 cGFzc3dvcmQ= --encrypt --in devices.txt --out devices.cry
```

Decrypt file:

```sh
java -jar cf-encrypt-<version>.jar file --password64 cGFzc3dvcmQ= --decrypt --in devices.cry --out devices.txt
```

## Usage for key extraction:

Only supported with the upcoming release 4.0 or newer.

```sh
java -jar cf-encrypt-<version>.jar key [(--private-key|--public-key)] [(--hex|--base64)] [--raw] <file>
```

## Arguments for key extraction:

       --private-key  : dump private key
       --public-key   : dump public key (default)
       --hex          : dump key in hexadecimal
       --base64       : dump key in base 64 (default)
       --raw          : dump raw key (skip ASN.1 header).

## Examples for key extraction:

Extract public key in base 64 (ASN.1):

```sh
java -jar cf-encrypt-<version>.jar key privkey.pem
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfLWngmsAJNXFkHmZnzGYFi1x4exUghzNR8zoAnLeHKcLVZY4BtJt9ra0a0Mrgpx220mbbgXZUpu/65Bi7SWypg==
```

Extract raw public key in hexadecimal (2x32 bytes):

```sh
java -jar target/cf-encrypt-3.13.0-SNAPSHOT.jar key privkey.pem --raw --hex
:0x7CB5A7826B0024D5C59079999F3198162D71E1EC54821CCD47CCE80272DE1CA70B55963806D26DF6B6B46B432B829C76DB499B6E05D9529BBFEB9062ED25B2A6
```

## Usage for PEM/P12 conversion into C-headers:

Only supported with the upcoming release 4.0 or newer.

```sh
java -jar cf-encrypt-<version>.jar toc <file>.pem [<out>]
```

or

```sh
java -jar cf-encrypt-<version>.jar toc <file>.p12 [<out>] --alias <alias> --pass <pass> [--keypass <keypass>]
```

Reads all sections of a PEM and converts each section into an separate C-header.

## Arguments for PEM conversion into C-headers:

       <file.pem> : file to convert. Ends with ".pem".
       <out>      : base for output filenames. Default is <file>.

## Arguments for P12 conversion into C-headers:

       <file.p12> : file to convert. Ends with ".p12".
       <out>      : base for output filenames. Default <alias>.
       <alias>    : alias to dump.
       <pass>     : passphrase for p12.
       <keypass>  : passphrase for private key in p12.

## Examples for PEM conversion into C-headers:

Convert PEM into C-header:

```sh
java -jar cf-encrypt-<version>.jar toc client.pem

PRIVATE KEY => client_private_key.h
CERTIFICATE => client_certificate.h
CERTIFICATE => client_certificate_1.h
```

### client_private_key.h:

```
"-----BEGIN PRIVATE KEY-----\n"
"MEEC.........................................................Clu\n"
"VT4l.....................w==\n"
"-----END PRIVATE KEY-----\n"
```

### client_certificate.h:

(client certificate, first in PEM)

```
"-----BEGIN CERTIFICATE-----\n"
"MIICATCCAaagAwIBAgIJAKRNkpfDa+OZMAoGCCqGSM49BAMCMFwxEDAOBgNVBAMT\n"
"B2NmLXJvb3QxFDASBgNVBAsTC0NhbGlmb3JuaXVtMRQwEgYDVQQKEwtFY2xpcHNl\n"
"IElvVDEPMA0GA1UEBxMGT3R0YXdhMQswCQYDVQQGEwJDQTAeFw0yNDExMDQxODE1\n"
"MzNaFw0yNjExMDQxODE1MzNaMF4xEjAQBgNVBAMTCWNmLWNsaWVudDEUMBIGA1UE\n"
"CxMLQ2FsaWZvcm5pdW0xFDASBgNVBAoTC0VjbGlwc2UgSW9UMQ8wDQYDVQQHEwZP\n"
"dHRhd2ExCzAJBgNVBAYTAkNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6bZx\n"
"uWya5viL6aCOGg4dSIg0roSB1q3XUaTM3Mm+42RPDjO/jjFVbOepKqJazFkTHIzl\n"
"WCZYyaFxwo3kaeA2I6NPME0wHQYDVR0OBBYEFH1nqOOasMUSdnS24HAWthoDN3A3\n"
"MAsGA1UdDwQEAwIHgDAfBgNVHSMEGDAWgBQYn8RsLYjczVn76FPSHWWK6iaqdzAK\n"
"BggqhkjOPQQDAgNJADBGAiEA5a11SdNWW02IUwlkQkuvwk8fHuVvFVHrKBIns0Kj\n"
"YkICIQC6sc6kd6XLMdPNFq/0TxzrXrgFgpx7EL4Iz7zXGjr1Cg==\n"
"-----END CERTIFICATE-----\n"
```

### client_certificate_1.h:

(CA certificate, second in PEM)

```
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
```
