![Californium logo](../../cf_64.png)

# CLI - Common Command Line Interface for Californium Clients

This module provides a common command line interface for several clients.

It applies the arguments and configure connectors and endpoints.

This module supports coap (plain UDP) and coaps (over DTLS).

For TCP support, a second module "cf-cli-tcp-netty" is provided. If TCP is required, use it by copying the built library of that "cf-cli-tcp-netty" into the folder of the client's jar, either manually or by maven plugin in the client's pom:

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

## Eclipse IDE - Run As - Java Application

The Eclipse IDE requires the "cf-cli-tcp-netty" project as well. Add that using the context menu "Properties" of the project, select in the left list the topic "Java Build Path" and there the tab "Projects". Add here the project "cf-cli-tcp-netty".
