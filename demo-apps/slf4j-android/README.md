# Android Log based implementation for slf4j

Optional alternative to "logback-android" or the original "org.slf4j:slf4-android".
Intended to be used for development as simple compiled in configured logger. The enabled logging levels are compiled in and are adjusted using "AndroidLoggerAdapter.Configuration("diwel")" in  "AndroidLoggerFactory". It maps the DEBUG and TRACE level also to INFO, therefore all log messages are printed without additional configuration.
 
This library is not build by the parent pom. It's a optional alternative and it depends on "com.google.android:android:4.1.1.4". It is only used, for android apps using californium during development. 

## Build using Maven

You need to have a working maven installation to build slf4j-android.
Then simply run the following from the library's root directory:

```sh
$ mvn clean install
```

## Using slf4j-android in Android Gradle Projects

This development library is not published to maven central and therefore requires to be build locally, see instructions above. 

```gradle
dependencies {
    ...
    // using logback as slf4j implementation
    // implementation 'com.github.tony19:logback-android:1.1.1-11'
    // using android Log as slf4j implementation - use for development only !
    implementation 'org.eclipse.californium:slf4j-android:2.0.0-SNAPSHOT'
}
```
## Third Party Content

### org.slf4j:slf4j-android

This product includes software developed by Quality Open Software 
[http://www.qos.ch](http://www.qos.ch). The project page is available at [https://www.slf4j.org](https://www.slf4j.org).

Your use of the **slf4j-android** is subject to the terms and conditions of the MIT License.
A copy of the license is contained in the file  [license.html](https://www.slf4j.org/license.html).


The binary code in **org.slf4j.slf4j-android-1.7.25.jar** is included with modifications. The original binary and source is available from [Maven Central](http://search.maven.org/#artifactdetails%7Corg.slf4j%7Cslf4j-android%7C1.7.25%7Cjar).
 
