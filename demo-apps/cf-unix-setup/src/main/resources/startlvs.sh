#! /bin/sh

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
# Prepare load-balancer node for DTLS CID load-balancer
#
# Requires su rights, execute with sudo!

if [ -z "$1" ]  ; then
    INTERFACE=
else 
    INTERFACE="-i $1"
fi


LOADBA_IP=192.168.178.118
NODE_1_IP=192.168.178.123
NODE_2_IP=192.168.178.124

# set ipvs UDP timeout to 15s
ipvsadm --set 0 0 15

echo "Remove IP LVS for port 5683 and 5684"

ipvsadm -D -u ${LOADBA_IP}:5683
ipvsadm -D -u ${LOADBA_IP}:5684

echo "Create IP LVS 5683"

ipvsadm -A -u ${LOADBA_IP}:5683 -s rr
ipvsadm -a -u ${LOADBA_IP}:5683 -r ${NODE_1_IP} -m
ipvsadm -a -u ${LOADBA_IP}:5683 -r ${NODE_2_IP} -m

echo "Create IP LVS 5684"

ipvsadm -A -u ${LOADBA_IP}:5684 -s rr
ipvsadm -a -u ${LOADBA_IP}:5684 -r ${NODE_1_IP} -m
ipvsadm -a -u ${LOADBA_IP}:5684 -r ${NODE_2_IP} -m

# NAT LB using DTLS 1.2 cid
# IPv4 layer, RFC 791, minimum 20 bytes, use IHL to calculate the effective size
# IPv6 layer, RFC 2460, "next header" => currently not supported :-)  
# UDP layer, RFC 768, 8 bytes
# DTLS 1.2 header first 3 bytes "19 fe fd" for TLS12_CID
# DTLS 1.2 header with cid 3 + 2 + 6

# firewall, drop non-DTLS 1.2  packages
echo "Create DTLS_FILTER"
iptables -t raw -N DTLS_FILTER
echo "Prepare DTLS_FILTER"
iptables -t raw -F DTLS_FILTER
iptables -t raw -A DTLS_FILTER -m u32 ! --u32 "0>>22&0x3C@ 7&0xF0FFFD=0x10FEFD && 0>>22&0x3C@ 5&0x0F=4:9" -j DROP

echo "Remove PREROUTING - DTLS FILTER $1"
iptables -t raw -D PREROUTING ${INTERFACE} -p udp --dport 5684 -j DTLS_FILTER
echo "Forward PREROUTING to DTLS NAT $1"
iptables -t raw -A PREROUTING ${INTERFACE} -p udp --dport 5684 -j DTLS_FILTER

# NAT with CID routing
echo "Create DTLS_NAT"
iptables -t nat -N DTLS_NAT
echo "Prepare DTLS_NAT"
iptables -t nat -F DTLS_NAT
iptables -t nat -A DTLS_NAT -m u32 --u32 "0>>22&0x3C@ 7&0xFFFFFF=0x19FEFD && 0>>22&0x3C@ 16&0xFF=1" -j DNAT --to-destination ${NODE_1_IP}
iptables -t nat -A DTLS_NAT -m u32 --u32 "0>>22&0x3C@ 7&0xFFFFFF=0x19FEFD && 0>>22&0x3C@ 16&0xFF=2" -j DNAT --to-destination ${NODE_2_IP}

echo "Remove PREROUTING to DTLS NAT $1"
iptables -t nat -D PREROUTING ${INTERFACE} -p udp --dport 5684 -j DTLS_NAT
echo "Forward PREROUTING to DTLS NAT $1"
iptables -t nat -A PREROUTING ${INTERFACE} -p udp --dport 5684 -j DTLS_NAT

echo "1" > /proc/sys/net/ipv4/ip_forward

# set DNAT timeout to 15s
echo "15" > /proc/sys/net/netfilter/nf_conntrack_udp_timeout
echo "15" > /proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream

# statistic:
# iptables -t nat -L -nvx
# reset statistics: 
# iptables -t nat -Z
# conntrack -L
# ipvsadm -L -n

