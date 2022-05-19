+++
title = "Kubernetes"
weight = 20

[asset]
  icon = "fas fa-globe"
  url = "https://github.com/eclipse/californium/wiki/Californium-as-k8s-service"
+++

Californium runs on k8s. Extensions to be used with k8s are provided in the [k8s module](https://github.com/eclipse/californium/tree/master/cf-utils/cf-cluster#californium-cf---k8s-support). For simple single pod deployments it supports a [Blue/Green Update with DTLS graceful restart](https://github.com/eclipse/californium/blob/master/cf-utils/cf-cluster/README.md#k8s-bluegreen-update-with-dtls-graceful-restart) simply on updating the image. For multiple pod deployments it supports additionally [DTLS Connection ID Cluster](https://github.com/eclipse/californium/blob/master/cf-utils/cf-cluster/README.md#californium-cf---k8s-built-in-support-for-dtls-connection-id-cluster).<br>
Unleash the power, prepare for huge numbers of devices and plenty messages.

