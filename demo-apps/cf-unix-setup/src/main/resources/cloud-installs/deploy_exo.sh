#!/bin/sh

#/*******************************************************************************
# * Copyright (c) 2021 Bosch.IO GmbH and others.
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
# requirements:
# 
# - activate account at https://portal.exoscale.com/register (please obey the resulting costs!)
# - install https://community.exoscale.com/documentation/tools/exoscale-command-line-interface/
#   and configure it
# - upload your ssh-key at https://portal.exoscale.com/compute/keypairs 
#   using the name "cali" or copy a different used name to "ssh_key_id" below.
#
# Adapt the the "vmsize" according your requirements and wanted price.
# See https://www.exoscale.com/pricing/ and
# run `exo compute instance create --help` to see the options.

ssh_key_id="cali"
vmsize="standard.small"

if [ "$1" = "create" ]  ; then
   echo "create exoscale server"

   exo compute security-group create cali-group

   exo compute security-group rule add cali-group \
    --description "ssh ipv4" \
    --protocol tcp \
    --network "0.0.0.0/0" \
    --port 22

   exo compute security-group rule add cali-group \
    --description "ssh ipv6" \
    --protocol tcp \
    --network "::/0" \
    --port 22

   exo compute security-group rule add cali-group \
    --description "coaps ipv4" \
    --protocol udp \
    --network "0.0.0.0/0" \
    --port 5684

   exo compute security-group rule add cali-group \
    --description "coaps ipv6" \
    --protocol udp \
    --network "::/0" \
    --port 5684
  
   exo compute instance create cali \
    --zone de-fra-1 \
    --disk-size 10 \
    --instance-type "${vmsize}" \
    --ipv6 \
    --ssh-key "${ssh_key_id}" \
    --cloud-init cloud-config.yaml \
    --security-group cali-group

   echo "wait to give vm time to finish the installation!"
   sleep 30
	
   ip=$(exo compute instance show cali -O text --output-template '{{ .IPAddress }}')

   echo "use: ssh root@${ip} to login!"

   exit 0
fi

if [ "$1" = "delete" ]  ; then
   echo "delete exoscale server"

   exo compute instance delete cali
   exo compute security-group delete cali-group --force

   exit 0
fi

echo "usage: (create|delete)"


