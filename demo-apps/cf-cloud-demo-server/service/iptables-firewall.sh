#!/bin/sh

#/*******************************************************************************
# * Copyright (c) 2024 Contributors to the Eclipse Foundation.
# * 
# * See the NOTICE file(s) distributed with this work for additional
# * information regarding copyright ownership.
# * 
# * This program and the accompanying materials
# * are made available under the terms of the Eclipse Public License v2.0
# * and Eclipse Distribution License v1.0 which accompany this distribution.
# * 
# * The Eclipse Public License is available at
# *    http://www.eclipse.org/legal/epl-v20.html
# * and the Eclipse Distribution License is available at
# *    http://www.eclipse.org/org/documents/edl-v10.html.
# * 
# * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
# * 
# ******************************************************************************/
#
# To install, cp <file> to /sbin/iptables-firewall.sh


# Limit PATH
PATH="/sbin:/usr/sbin:/bin:/usr/bin"

# iptables configuration
firewall_start() {
  # Define https forward
  iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8080 2> /dev/null
  ip6tables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8080 2> /dev/null
  echo "start https forwarding ..."
  iptables -t nat -I PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8080
  ip6tables -t nat -I PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8080
  echo "started https forwarding"
}

# clear iptables configuration
firewall_stop() {
  # Delete https forward
  echo "stop https forwarding ..."
  iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8080
  ip6tables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8080
  echo "stopped https forwarding"
}

# execute action
case "$1" in
  start|restart)
    echo "Starting firewall"
    firewall_start
    ;;
  stop)
    echo "Stopping firewall"
    firewall_stop
    ;;
esac

