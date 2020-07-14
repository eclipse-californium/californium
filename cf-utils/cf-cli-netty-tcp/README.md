# CLI-NETTY-TCP - Common Command Line Interface Netty TCP support

This module provides TCP support for the common command line interface.

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
