Californium (Cf) CoAP framework
===============================

Californium is a Java implementation of [CoAP](http://tools.ietf.org/html/rfc7252) for the IoT backend and less constrained IoT devices.
Thus, the focus is on scalability and usability instead of resource-efficiency like for embedded devices.
Yet Californium is also suitable for embedded JVMs.

Californium (Cf) consists of the following components:

1. [Element-Connector](element-connector): UDP socket abstraction
1. [Scandium](scandium): DTLS implementation
1. [Californium](core): Core CoAP libraries
1. [Tools](https://github.com/eclipse/californium.tools): Standalone tools such as the resource directory
1. [Actinium](https://github.com/eclipse/californium.actinium): RESTful JavaScript runtime for IoT mashups

Because of dependencies, the components need to be build in the given order.
More information can be found on [Californium's home page at Eclipse](http://www.eclipse.org/californium/) and [http://coap.technology/](http://coap.technology/).

Contact
-------

A bug, an idea, an issue? Join the [Mailing list](https://dev.eclipse.org/mailman/listinfo/cf-dev)
