![Californium logo](../../cf_64.png)

# File encryption for configuration files with credentials

In order slightly better protect credentials in configuration files, this tool encrypts such files.

The format is quite simple:

- 2 bytes cipher code
- 1 bytes nonce length
- n bytes nonce
- p bytes encrypted payload
- m bytes mac (depending on the selected cipher)

# Download

[Eclipse Release Repository](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-encrypt/3.9.0/cf-encrypt-3.9.0.jar)

#Usage

Usage:

```sh
java -jar cf-encrypt-<version>.jar --password64 <password-base64> [(--encrypt [--cipher <cipher>]|--decrypt)] [--out <file>] [--in] <file>
```

## Arguments

    --password64            : password in base 64 encoding
    --in                    : input file name
    --out                   : output file name. Default replaces input file
    --encrypt or --decrypt  : encrypt file or decrypt file
    --cipher                : cipher to encrypt file. On decrypt the cipher is read from file.
                              Supported values are "AES/CBC/128", "AES/CBC/256", "AES/GCM/128",
                              "AES/GCM/256", "ARIA/GCM/128", and "ARIA/GCM/256". The JCE must
                              also support the cipher in order to be applied.

