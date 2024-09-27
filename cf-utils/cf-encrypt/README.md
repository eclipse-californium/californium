![Californium logo](../../cf_64.png)

# File encryption and key extraction

This utility app provides encryption and decryption of configuration files as well as starting with version 3.13 extracting key data from .pem files in order to pass them to the device clients.

# Download

[Eclipse Release Repository (3.12)](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-encrypt/3.12.0/cf-encrypt-3.12.0.jar)

#Usage

Usage:

```sh
java -jar cf-encrypt-<version>.jar file
java -jar cf-encrypt-<version>.jar key
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

Only supported with the upcoming release 3.13 or newer.

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
