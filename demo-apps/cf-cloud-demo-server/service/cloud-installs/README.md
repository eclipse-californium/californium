![Californium logo](../../../../cf_64.png)

# Californium (Cf) - Cloud Demo Server

## Install scripts

**Note:** The installation contains "secrets", e.g. to store the DTLS state or to read the device credentials. Therefore a dedicated cloud-VM must be used and the access to that cloud-VM must be protected! This basic/simple setup also uses the "root" user. Please replace/add a different user according your security policy.

This instructions assumes to be already common with tools used around "headless compute units" and "cloud computing". It does not contain the basic instruction for using them. However, quite a lot of steps are already executed by the scripts and so you don't need to do them manually. In cases of errors it may be important that you are common with this tools in order to solve them. It may be also required to apply more specific security hardening. That is usually defined by your company's security team, it depends on the used cloud and is therefore not provided here.

## Tools

[**ssh, scp**](https://www.openssh.com/manual.html): remote shell to execute shell commands on the headless compute unit and to transfer files to it. The scripts assume, that certificates are used for authentication and the user is common with that. It requires to import the public key in the cloud-account in order to use it when creating a compute unit. The local filename and the id used in the cloud may differ, it's only the public key, which must match. (e.g. local file system "~/.ssh/id_ed25519.pub" and cloud "cali"). Advanced users may change this names, if that is required, see [deploy-dev.sh](./deploy-dev.sh) for details.

**providers's CLI tools**: required to create and delete the compute unit. The network configuration is also done with this tools. To specify the OS and tools to install when creating a compute unit [cloudinit](https://cloudinit.readthedocs.io/en/latest/index.html) is used with [cloud-config-dev.yaml](./cloud-config-dev.yaml) as configuration.

- [ExoScale CLI](https://community.exoscale.com/documentation/tools/exoscale-command-line-interface/)
- [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-welcome.html)
- [Digital Ocean CLI](https://docs.digitalocean.com/reference/doctl/)

## Scripts

The [deploy-dev.sh](./deploy-dev.sh) is the central script for creating a compute unit, install this application or delete the compute unit. The script contains the general tasks (executed via `ssh`/`scp`) and includes one of the provider's scripts ([provider-aws.sh](./provider-aws.sh), [provider-do.sh](./provider-do.sh) or [provider-exo.sh](./provider-exo.sh))to execute tasks using the provider's CLI tools.

The scripts are using several additional tools (e.g. `sed` or `grep`), which needed to be installed ahead. Each script contains therefore a section of required tools and other requirements close to the header, e.g. [./deploy-dev.sh](./deploy-dev.sh#L22-L47).
