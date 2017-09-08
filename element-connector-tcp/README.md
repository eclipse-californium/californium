element-connector-tcp
=====================

The element-connector-tcp is a TCP implementation for element-connector based on netty.

Maven
-----

Usually the element-connector is already included as Maven dependency in the
Californium projects. Alternatively, use `mvn clean install` in the root
directory to build and install the artifact locally.

The Maven repositories are:

```xml
  <repositories>
    ...
    <repository>
      <id>repo.eclipse.org</id>
      <name>Californium Repository - Releases</name>
      <url>https://repo.eclipse.org/content/repositories/californium-releases/</url>
    </repository>
    <repository>
      <id>repo.eclipse.org</id>
      <name>Californium Repository - Snapshots</name>
      <url>https://repo.eclipse.org/content/repositories/californium-snapshots/</url>
    </repository>
    ...
  </repositories>
```

Eclipse
-------

The project also includes the project files for Eclipse. Make sure to have the
following before importing the project:

* [Eclipse EGit](http://www.eclipse.org/egit/)
* [m2e - Maven Integration for Eclipse](http://www.eclipse.org/m2e/)
* UTF-8 workspace text file encoding (Preferences &raquo; General &raquo; Workspace)

Then choose *[Import... &raquo; Git &raquo; Projects from Git &raquo; Local]*
to import `californium.element-connector-tcp` into Eclipse.
