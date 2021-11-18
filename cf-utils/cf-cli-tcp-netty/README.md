![Californium logo](../../cf_64.png)

# CLI-TCP-NETTY - Common Command Line Interface TCP Netty.IO support

This module provides TCP support using netty.io for the common command line interface.

If TCP is required, use it by copying the built library into the folder of the client's jar, either manually or by maven plugin in the client's pom:

```xml
	<plugin>
		<artifactId>maven-dependency-plugin</artifactId>
		<executions>
			<execution>
				<id>copy-installed</id>
				<phase>install</phase>
				<goals>
					<goal>copy</goal>
				</goals>
				<configuration>
					<artifactItems>
						<artifactItem>
							<groupId>${project.groupId}</groupId>
							<artifactId>cf-cli-tcp-netty</artifactId>
							<version>${project.version}</version>
							<type>${project.packaging}</type>
						</artifactItem>
					</artifactItems>
					<outputDirectory>target</outputDirectory>
				</configuration>
			</execution>
		</executions>
	</plugin>
```

If the application is intended to be start by "java -jar xxx.jar", also a classpath entry in the manifest is required.

```xml
	<plugin>
		<artifactId>maven-assembly-plugin</artifactId>
		<configuration>
			<archive>
				<manifestEntries>
					<!-- support tcp, if module library is available -->
					<Class-Path>cf-cli-tcp-netty-${project.version}.jar</Class-Path>
				</manifestEntries>
			</archive>
		</configuration>
	</plugin>
```

Alternatively adapt the dependency from "cf-cli" to "cf-cli-tcp-netty" in the client's pom.

```xml
  <dependencies>
    ...
    <dependency>
            <groupId>org.eclipse.californium</groupId>
            <artifactId>cf-cli-tcp-netty</artifactId>
            <version>${project.version}</version>
    </dependency>
    ...
  </dependencies>
```

