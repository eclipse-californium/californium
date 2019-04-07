#! /bin/sh

#/*******************************************************************************
# * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
# * 
# * All rights reserved. This program and the accompanying materials
# * are made available under the terms of the Eclipse Public License v1.0
# * and Eclipse Distribution License v1.0 which accompany this distribution.
# * 
# * The Eclipse Public License is available at
# *    http://www.eclipse.org/legal/epl-v10.html
# * and the Eclipse Distribution License is available at
# *    http://www.eclipse.org/org/documents/edl-v10.html.
# * 
# * Contributors:
# *    Achim Kraus (Bosch Software Innovations GmbH) - initial script
# ******************************************************************************/
#
# Prepare route to load-balancer node for cluster node
# 
# Requires su rights, execute with sudo!

ip route del default
# adapt this according your ip subnet setup
ip route del 192.168.178.0/24

# adapt this according your load-balancer ip and interface setup
ip route add 192.168.178.118/32 dev wlan0
# adapt this according your load-balancer ip
ip route add default via 192.168.178.118
# add routes to other nodes in the subnet, if required
