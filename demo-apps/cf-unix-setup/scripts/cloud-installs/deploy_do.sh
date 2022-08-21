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
#
# Available regions:
# run `doctl compute run `doctl compute size list` list`

name=cali
ssh_key_id="7d:2a:03:72:eb:d6:95:52:1d:7f:77:73:22:35:0f:93"
vmsize="s-2vcpu-2gb"

get_ip() {
   ip=$(doctl compute droplet get ${name} --template {{.PublicIPv4}})
   echo "vm-ip: ${ip}"
}

wait_vm_ready() {
   status=$(doctl compute droplet get ${name} --template {{.Status}})
   while [ "${status}" != "active" ] ; do
      echo "vm: ${status}, waiting for active"
      sleep 10
      status=$(doctl compute droplet get ${name} --template {{.Status}})
   done
   echo "vm: ${status}"
}

wait_cloud_init_ready() {
   status=$(ssh -o "StrictHostKeyChecking=accept-new" root@${ip} "cloud-init status")

   while [ "${status}" != "status: done" ] ; do
      echo "cloud-init: ${status}, waiting for done"
      sleep 10
      status=$(ssh -o "StrictHostKeyChecking=accept-new" root@${ip} "cloud-init status")
   done
   echo "cloud-init: ${status}"
}

if [ "$1" = "create" ]  ; then
   echo "create digitalocean firewall ${name}"

   doctl compute tag create ${name}

   doctl compute firewall create \
     --name ${name} \
     --tag-names ${name} \
     --inbound-rules="protocol:tcp,ports:22,address:0.0.0.0/0,address:::/0 protocol:udp,ports:5684,address:0.0.0.0/0,address:::/0" \
     --outbound-rules="protocol:tcp,ports:all,address:0.0.0.0/0,address:::/0 protocol:udp,ports:all,address:0.0.0.0/0,address:::/0 protocol:icmp,address:0.0.0.0/0,address:::/0"

   echo "create digitalocean server ${name}, may take a couple of minutes to complete."
   
   doctl compute droplet create ${name} \
    --tag-name ${name} \
    --image "ubuntu-20-04-x64" \
    --enable-ipv6 \
    --region "fra1" \
    --size "${vmsize}" \
    --ssh-keys "${ssh_key_id}" \
    --user-data-file "cloud-config.yaml" \
    --wait 	

   echo "wait to give vm time to finish the installation!"

   wait_vm_ready

   doctl compute droplet get ${name} --format ID,PublicIPv4,PublicIPv6

   get_ip

   wait_cloud_init_ready
	
   echo "use: ssh root@${ip} to login!"

   exit 0
fi

if [ "$1" = "delete" ]  ; then
   echo "delete digitalocean server ${name}"

   get_ip

   doctl compute droplet delete ${name}

   id=$(doctl compute firewall list --format "ID,Name" | grep ${name} | cut -sd ' ' -f 1)

   if [ -n "${id}" ] ; then
      echo "delete digitalocean fw ${id}"
      doctl compute firewall delete ${id}
   fi
   
   doctl compute tag delete ${name}

   echo "Please verify the successful deletion via the Web UI."

   echo "Remove the ssh trust for ${ip} with:"
   echo "ssh-keygen -f ~/.ssh/known_hosts -R \"${ip}\""

   exit 0
fi

echo "usage: (create|delete)"

