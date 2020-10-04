#!/bin/sh

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
#
# Disables DTLS firewall using iptables
# Not used for load-balancer setup
#
# Requires su rights, execute with sudo!

if [ -z "$1" ]  ; then
    INTERFACE=
else 
    INTERFACE="-i $1"
fi

echo "Clean DTLS filter"
iptables -F DTLS_FILTER
echo "Remove INPUT to DTLS filter $1"
iptables -D INPUT ${INTERFACE} -p udp --dport 5684 -j DTLS_FILTER
echo "Delete DTLS filter"
iptables -X DTLS_FILTER

