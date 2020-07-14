# CLI - Common Command Line Interface for Californium Clients

This module provides a common command line interface for several clients.

It applies the arguments and configure connectors and endpoints.

This module supports coap (plain UDP) and coaps (over DTLS).

For TCP support, a second module "cf-cli-netty-tcp" is provided. If TCP is required, use it by copying the built library of that "cf-cli-netty-tcp" into the folder of the client's jar, either manually or by maven plugin in the client's pom:

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
							<artifactId>cf-cli-netty-tcp</artifactId>
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

Alternatively adapt the dependency from "cf-cli" to "cf-cli-netty-tcp" in the client's pom.

```xml
  <dependencies>
    ...
    <dependency>
            <groupId>org.eclipse.californium</groupId>
            <artifactId>cf-cli-netty-tcp</artifactId>
            <version>${project.version}</version>
    </dependency>
    ...
  </dependencies>
```
