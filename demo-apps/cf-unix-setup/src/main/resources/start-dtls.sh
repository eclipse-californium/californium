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
# Enables DTLS firewall using iptables
# Not used for load-balancer setup
#
# IPv4 layer, RFC 791, minimum 20 bytes, use IHL to calculate the effective size
# IPv6 layer, RFC 2460, "next header" => currently not supported :-)  
# UDP layer, RFC 768, 8 bytes
# DTLS 1.2 header first 3 bytes "14 - 19 fe fd"
# check for "1? fe fd" and "?4-?9"
#
# Requires su rights, execute with sudo!

if [ -z "$1" ]  ; then
    INTERFACE=
else 
    INTERFACE="-i $1"
fi

echo "Create DTLS_FILTER"
iptables -N DTLS_FILTER
echo "Prepare DTLS_FILTER"
iptables -F DTLS_FILTER
iptables -A DTLS_FILTER -m u32 ! --u32 "0>>22&0x3C@ 7&0xF0FFFF=0x10FEFD && 0>>22&0x3C@ 5&0x0F=4:9" -j DROP

echo "Remove INPUT to DTLS filter $1"
iptables -D INPUT ${INTERFACE} -p udp --dport 5684 -j DTLS_FILTER
echo "Forward INPUT to DTLS filter"
iptables -A INPUT ${INTERFACE} -p udp --dport 5684 -j DTLS_FILTER

# statistic:
# iptables -L -n -v -x
# reset statistics: 
# iptables -Z