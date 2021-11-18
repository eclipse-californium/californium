![Californium logo](../../cf_64.png)

# Californium as old style unix systemd service

Yes, there are more modern service types out, but I still prefer the plain systemd. It requires some more steps, but it has close to no uncontrolled dependencies and runs very efficiently. Nevertheless, if someone else want to publish an other setup, feel free to contribute it.

## Manual Installation

### Requirements

As mention above, one of my reasons for using a unix systemd service is, it requires nearly nothing else.
Though Californium is implemented in java without own UI, you need a Java Runtime Environment, headless. The Java Development Kit will do it naturally as well and none headless also. The minimum required version is "1.7". I mainly use "1.8" and "java 11". The installation of that Java depends on your unix distribution. Some came with an already installed java. Therefore first check, if it's already install executing 

```
java -version
```

in a command-line-terminal. If it's already installed, the output will be similar to:

```
openjdk version "1.8.0_265"
OpenJDK Runtime Environment (build 1.8.0_265-8u265-b01-0ubuntu2~18.04-b01)
OpenJDK 64-Bit Server VM (build 25.265-b01, mixed mode)
```

The variant and version may vary, but usually all from java "1.7" on will do it and all variants (jre or jdk, maybe headless) will work. If the command fails, the error message usually contains the information what to do. Using Ubuntu 18.04 LTS you may install it with:

```
sudo apt install openjdk-8-jre-headless
```
or
```
sudo apt install openjdk-11-jre-headless
```

and check the result again with `java -version`. If that's done, then copy your californium.jar to the host. If you want to run the cf-plugtest-server, it's the "<californium>/demo-apps/run/cf-plugtest-server-???.jar" (replace the ??? with the version your using, e.g. 3.0.0). The [cf-plugtest-server-3.0.0.jar](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-plugtest-server/3.0.0/cf-plugtest-server-3.0.0.jar) is also available for download.

### Preparation

For a systemd service it's a good practice, to run it as "no root, no login user". Therefore add such a user "cali" to your system.

```
sudo adduser --system --home /home/cali --disabled-login cali
```
 
([Download template to copy lines from](src/main/resources/install.sh) )

Check, if "/home/cali" have been created successfully.
Now move the californium.jar into the "/home/cali" folder using "cf-plugtest-server-update.jar" as destination

```
sudo mv cf-plugtest-server-???.jar /home/cali/cf-plugtest-server-update.jar
```

(Don't forget to replace the ??? with your version.)
Create a service configuration file "cali.service"

```
[Unit]
Description=Californium Plugtest Server
BindsTo=network-online.target
After=network-online.target
RequiresMountsFor=/home

[Service]
Type=simple
TasksMax=256
User=cali
WorkingDirectory=/home/cali
Environment="JAR=cf-plugtest-server.jar"
Environment="ARGS=--no-loopback --store-file=connections.bin --store-max-age=24 --store-password64=TDNLOmJTWi13JUs/YGdvNA=="
Environment="OPTS=-XX:MaxRAMPercentage=75 -Dlogback.configurationFile=./logback.xml"
ExecStartPre=/bin/cp -u cf-plugtest-server-update.jar cf-plugtest-server.jar
ExecStart=/usr/bin/java $OPTS -jar ${JAR} $ARGS
RestartSec=10
Restart=always
OOMPolicy=stop

[Install]
WantedBy=multi-user.target
```

[Download "cali.service" file](src/main/resources/cali.service)

Depending on the number of connectors, the value of `TasksMax` in the service description must be adapted. There may be also a limit of  `TasksMax` from the machine it runs on. Especially, if a container solution is used instead of VM.  Check, if  "/proc/user_beancounters" is available, and if so, check the number of "numproc". The required number depends also from the used configuration value in the "Californium???3.properties". Check the values for receiving and sending threads per connector.  

**Note:** the number of connectors is not the number of connections. A connector can run many connections and doesn't require to use a high number of tasks.  

**Note:** `-XX:MaxRAMPercentage=75` is supported from java 11 on. For older java versions please adjust the size  of the java heap according your needs using `-Xmx`, e.g. `-Xmx1000m`.

Copy the "cali.service" file into the "/etc/systemd/system" folder. Use 

```
sudo systemctl daemon-reload
```

to update systemd with the new service.

## `Cloud-Init` - Automatic Cloud VM Installation

If you want to install Californium in a cloud vm, some providers supports [cloud-init](https://cloudinit.readthedocs.io/en/latest/), which makes it easier to define an automatic installation. How that is applied and which additional steps must be take, depends on your provider.

```
package_upgrade: true

packages:
 - openjdk-17-jre-headless
 - fail2ban

disable_root: false

users:
 - name: cali
   gecos: (Cf) Californium Server
   lock_passwd: true
   no_user_group: true

runcmd:
 - [ wget, "https://github.com/eclipse/californium/raw/master/demo-apps/cf-unix-setup/src/main/resources/cali.service", -O, "/etc/systemd/system/cali.service" ]
 - [ wget, "https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-plugtest-server/3.0.0/cf-plugtest-server-3.0.0.jar", -O, "/home/cali/cf-plugtest-server-update.jar" ]
 - [ wget, "https://github.com/eclipse/californium/raw/master/demo-apps/cf-plugtest-server/src/main/resources/logback.xml", -O, "/home/cali/logback.xml" ]
 - [ systemctl, start, cali ]
 - [ systemctl, enable, cali ]
 - [ wget, "https://github.com/eclipse/californium/raw/master/demo-apps/cf-unix-setup/src/main/resources/fail2ban/cali2fail.conf", -O, "/etc/fail2ban/jail.d/cali2fail.conf" ]
 - [ wget, "https://github.com/eclipse/californium/raw/master/demo-apps/cf-unix-setup/src/main/resources/fail2ban/cali.conf", -O, "/etc/fail2ban/filter.d/cali.conf" ]
 - [ systemctl, restart, fail2ban ]

```

[cloud-config.yaml](src/main/resources/cloud-installs/cloud-config.yaml)

This updates all packages, installs a java runtime and [fail2ban](#fail2ban). It the follows the manual installation, copying files and configuring the systemd service. The used files are downloaded from this git repository and the [Eclipse Release Repository](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-plugtest-server/3.0.0/cf-plugtest-server-3.0.0.jar) 

### Installation on Exoscale cloud

[Exoscale - European cloud hosting](https://www.exoscale.com/)

[deploy_exo.sh](src/main/resources/cloud-installs/deploy_exo.sh)

This script uses the exoscale cli (exo) to create a compute instance and the [cloud-config.yaml](src/main/resources/cloud-installs/cloud-config.yaml) to configure and install the [Californium Plugtest Server](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-plugtest-server/3.0.0/cf-plugtest-server-3.0.0.jar).

Features: IPv4, IPv6, Firewall

For further instructions see the comments in that script.

### Installation on DigitalOcean cloud

[DigitalOcean - The developer cloud](https://www.digitalocean.com/)

[deploy_do.sh](src/main/resources/cloud-installs/deploy_do.sh)

This script uses the digitalocean cli (doctl) to create a compute droplet and the [cloud-config.yaml](src/main/resources/cloud-installs/cloud-config.yaml) to configure and install the [Californium Plugtest Server](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-plugtest-server/3.0.0/cf-plugtest-server-3.0.0.jar) 

Features: IPv4, IPv6, Firewall

For further instructions see the comments in that script.

### Installation on Google cloud

[Google Cloud - Cloud-Computing-Service](https://cloud.google.com)

[deploy_gcloud.sh](src/main/resources/cloud-installs/deploy_gcloud.sh)

This script uses the google cloud API (gcloud) to create a compute instance and the [cloud-config.yaml](src/main/resources/cloud-installs/cloud-config.yaml) to configure and install the [Californium Plugtest Server](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-plugtest-server/3.0.0/cf-plugtest-server-3.0.0.jar) 

Features: IPv4, Firewall

For further instructions see the comments in that script.

### Installation on Azure cloud

[Azure - Cloud-Computing-Service](https://azure.microsoft.com)

[deploy_azure.sh](src/main/resources/cloud-installs/deploy_azure.sh)

This script uses the azure cloud API (az) to create a vm and the [cloud-config.yaml](src/main/resources/cloud-installs/cloud-config.yaml) to configure and install the [Californium Plugtest Server](https://repo.eclipse.org/content/repositories/californium-releases/org/eclipse/californium/cf-plugtest-server/3.0.0/cf-plugtest-server-3.0.0.jar) 

Features: IPv4, Firewall

For further instructions see the comments in that script.

## Handling of the "cali.service"

To start the service, use

```
sudo systemctl start cali
```
 
Using

```
sudo systemctl status cali -n 200
```

you will see the startup logging messages. Or

```
sudo journalctl -n 200 -f -b -u cali
```

for more logging messages.

```
sudo systemctl stop cali
```

will stop the service again.

If you want the service to autostart on boot, use

```
sudo systemctl enable cali
```

to stop that

```
sudo systemctl disable cali
```

## Apply jar updates

Move the updated californium.jar into the "/home/cali" folder using "cf-plugtest-server-update.jar" as destination

```
sudo mv cf-plugtest-server-???.jar /home/cali/cf-plugtest-server-update.jar
```

Restart the service

```
sudo systemctl restart cali
```

If "cf-plugtest-server.jar" is updated in-place when running,  that my cause unintended exceptions, which prevents Californium from successfully gracefull-restart of the dtls state.  Therefore the "cf-plugtest-server-update.jar" is used for staging and copied to "cf-plugtest-server.jar" on (re-)starting the service.

## Hardening - already done by systemd

Someone will ask, what must be done to restart the service when it crashes. With systemd that's very easy, it's build in.

```
RestartSec=10
Restart=always
OOMPolicy=stop
```

will restart the service after a quiet period of 10 seconds.

## fail2ban

To ban some host from sending malicious messages, Californium support to write the source ip-addresses of  malicious messages into a special log file.
The plugtest-server uses logback for logging, and configures therefore a file-appender and configures the logger "org.eclipse.californium.ban" to use that.

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
[2021-11-03 12:48:34]	coap+tcp TCP Message has invalid token length (> 8) 14; 6E636F64696E673A TCP Ban: ??.??.??.??
[2021-11-03 12:48:34]	coap+tcp TCP Message has invalid token length (> 8) 13; 0D0A416363657074 TCP Ban: ??.??.??.??
[2021-11-03 12:48:34]	coap+tcp Not a CoAP response code: 3.05; 67653A20656E2D55 TCP Ban: ??.??.??.??
[2021-11-03 12:48:34]	coap+tcp illegal message code; 302E390D0A TCP Ban: ??.??.??.??
[2021-11-03 13:09:42]	coaps Option Content-Format value of 3 bytes must be in range of [0-2] bytes. 5203ABD914E9B763 DTLS Ban: ??.??.??.??
[2021-11-03 13:10:11]	coaps Option Content-Format value of 3 bytes must be in range of [0-2] bytes. 5203ABDA15E9B763 DTLS Ban:??.??.??.??
```

### fail2ban - installation

```
sudo apt install fail2ban
```

To configure fail2ban, define a filter:

```
[INCLUDES]

before = common.conf

[Definition]

failregex = Ban:\s+<HOST>
```

and copy [cali.conf](src/main/resources/fail2ban/cali.conf) into folder "/etc/fail2ban/filter.d". That selects the `<HOST>` after the tag "Ban:".

Then create a jail:

```
[DEFAULT]
bantime  = 1800
findtime = 300
maxretry = 3

[cali-udp]
enabled  = true
port     = 5683,5684
protocol = udp
filter = cali
logpath  = /home/cali/logs/ban.log
maxretry = 3

[cali-tcp]
enabled  = true
port     = 5683,5684
protocol = tcp
filter = cali
logpath  = /home/cali/logs/ban.log
maxretry = 3
```

and copy [cali2fail.conf](src/main/resources/fail2ban/cali2fail.conf) into folder "/etc/fail2ban/jail.d". That applies the before defined filter to the "ban.log" and "jails" `<HOST>` on 3 failures within the last 5 (300s) minutes for 30 minutes (1800s).

To check the jail, use

```
sudo fail2ban-client status cali-udp

Status for the jail: cali-udp
|- Filter
|  |- Currently failed:	1
|  |- Total failed:	210
|  `- File list:	/home/cali/logs/ban.log
`- Actions
   |- Currently banned:	0
   |- Total banned:	7
   `- Banned IP list:	
```
