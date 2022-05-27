+++
fragment = "item"
#disabled = false
date = "2022-05-19"
weight = 120
background = "light"
align = "left"

title = "Element-Connector"

[asset]
  icon = "fas fa-link"

[[buttons]]
  text = "Introduction"
  url = "https://github.com/eclipse/californium/tree/main/element-connector#element-connector"
[[buttons]]
  text = "Repository"
  url = "https://github.com/eclipse/californium/tree/main/element-connector"
+++

The element-connector abstracts from the different transports CoAP can use.
It provides the basic UDPConnector as well as the interface to implement new connectors like the DtlsConnector of Scandium.
<br>
It is also the place for common components and utilities, e.g to read certificate based credentials.
Since version 3.0 this includes also the new configuration.
