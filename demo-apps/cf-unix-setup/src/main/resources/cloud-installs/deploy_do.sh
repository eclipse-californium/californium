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
# - activate account at https://www.digitalocean.com/ (please obey the resulting costs!)
# - install https://docs.digitalocean.com/reference/doctl/how-to/install/
# - upload your ssh-key to https://cloud.digitalocean.com/account/security and copy 
#   the fingerprint of the ssh-key to "ssh_key_id" below.
#
# Adapt the the "vmsize" according your requirements and wanted price.
# See https://www.digitalocean.com/pricing/ and
# run `doctl compute size list` to see the options.

ssh_key_id="5a:1a:63:b7:81:56:0f:57:1c:b1:30:ba:54:ef:7a:cb"
vmsize="s-2vcpu-2gb-amd"

if [ "$1" = "create" ]  ; then
   echo "create digitalocean server"
   
   doctl compute droplet create cali \
    --image "ubuntu-20-04-x64" \
    --enable-ipv6 \
    --region "fra1" \
    --size "${vmsize}" \
    --ssh-keys "${ssh_key_id}" \
    --user-data-file "cloud-config.yaml" 	

   echo "wait to give vm time to finish the installation!"
   sleep 30 
	
   doctl compute droplet get cali --format PublicIPv4,PublicIPv6

   ip=$(doctl compute droplet get cali --template {{.PublicIPv4}})

   echo "use: ssh root@${ip} to login!"

   exit 0
fi

if [ "$1" = "delete" ]  ; then
   echo "delete digitalocean server"

   doctl compute droplet delete cali

   exit 0
fi

echo "usage: (create|delete)"

