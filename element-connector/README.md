element-connector
=================

The element-connector is a Java socket abstraction for UDP, DTLS, TCP, etc.
It is used to modularize Californium (Cf) and add DTLS support through the
standalone Scandium (Sc) project. Further projects can add so add different
transports independently (e.g., TCP, SMS, or special sockets when running in
an optimized VM such as Virtenio's PreonVM).

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
to import `californium.element-connector` into Eclipse.
