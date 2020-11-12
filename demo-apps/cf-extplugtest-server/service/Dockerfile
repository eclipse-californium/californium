#/*******************************************************************************
# * Copyright (c) 2020 Bosch.IO GmbH and others.
# * 
# * All rights reserved. This program and the accompanying materials
# * are made available under the terms of the Eclipse Public License v2.0
# * and Eclipse Distribution License v1.0 which accompany this distribution.
# * 
# * The Eclipse Public License is available at
# *    http://www.eclipse.org/legal/epl-v20.html
# * and the Eclipse Distribution License is available at
# *    http://www.eclipse.org/org/documents/edl-v10.html.
# * 
# * Contributors:
# *    Achim Kraus (Bosch.IO GmbH) - initial script
# ******************************************************************************/

FROM docker.io/openjdk:11-jre-slim

RUN mkdir /opt/app
COPY ./CaliforniumReceivetest.properties ./target/cf-extplugtest-server-2.6.0-SNAPSHOT.jar /opt/app/
#COPY ./CaliforniumPlugtest.properties /opt/app

#EXPOSE 5683/udp
#EXPOSE 5683/tcp
#EXPOSE 5684/udp
#EXPOSE 5684/tcp
EXPOSE 5783/udp
#EXPOSE 5783/tcp
EXPOSE 5784/udp
#EXPOSE 5784/tcp
EXPOSE 5884/udp

CMD ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75", "-jar", "/opt/app/cf-extplugtest-server-2.6.0-SNAPSHOT.jar", "--no-plugtest", "--no-tcp", "--benchmark", "--k8s-dtls-cluster", ":5784;:5884;5884"]
