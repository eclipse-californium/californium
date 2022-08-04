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
# requirements:
#
# - activate account at https://www.digitalocean.com/ (please obey the resulting costs!)
# - install https://docs.digitalocean.com/reference/doctl/how-to/install/ . That requires
#   to create an API access token.
# - upload your ssh-key to https://cloud.digitalocean.com/account/security and copy 
#   the fingerprint of the ssh-key to "ssh_key_id" below.
#
# Adapt the the "vmsize" according your requirements and wanted price.
# See https://www.digitalocean.com/pricing/ and
# run `doctl compute size list` to see the options.
#
# Available regions:
# run `doctl compute region list`
#
# Available images:
# run `doctl compute image list-distribution`
#
# required sh commands:
# - grep
# - cut

vmsize="s-2vcpu-2gb"
vmimage="ubuntu-22-04-x64"

get_ip() {
   ip=$(doctl compute droplet get ${name} --template {{.PublicIPv4}})
   echo "vm-ip  : ${ip}"
   ipv6=$(doctl compute droplet get ${name} --template {{.PublicIPv6}})
   echo "vm-ipv6: ${ipv6}"
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

provider_create_cloud_vm() {
   echo "create digitalocean firewall ${name}"

   doctl compute tag create ${name}

   doctl compute firewall create \
     --name ${name} \
     --tag-names ${name} \
     --inbound-rules="protocol:tcp,ports:22,address:0.0.0.0/0,address:::/0 protocol:tcp,ports:80,address:0.0.0.0/0,address:::/0 protocol:tcp,ports:443,address:0.0.0.0/0,address:::/0 protocol:udp,ports:5684,address:0.0.0.0/0,address:::/0" \
     --outbound-rules="protocol:tcp,ports:all,address:0.0.0.0/0,address:::/0 protocol:udp,ports:all,address:0.0.0.0/0,address:::/0 protocol:icmp,address:0.0.0.0/0,address:::/0"

   echo "create digitalocean server ${name}, may take a couple of minutes to complete."

   # get ssh_key ID from Name
   do_ssh_key_id=$(doctl compute ssh-key list --format "ID,Name" | grep ${ssh_key_id} | cut -sd ' ' -f 1)
  
   doctl compute droplet create ${name} \
    --tag-name ${name} \
    --image "${vmimage}" \
    --enable-ipv6 \
    --region "fra1" \
    --size "${vmsize}" \
    --ssh-keys "${do_ssh_key_id}" \
    --user-data-file "${cloud_config}" \
    --wait 	

   echo "wait to give vm time to finish the installation!"

   wait_vm_ready

   doctl compute droplet get ${name} --format ID,PublicIPv4,PublicIPv6

   get_ip

   wait_cloud_init_ready
	
   echo "use: ssh root@${ip} to login!"
}

provider_delete_cloud_vm() {
   echo "delete digitalocean server ${name}"

   doctl compute droplet delete ${name}

   id=$(doctl compute firewall list --format "ID,Name" | grep ${name} | cut -sd ' ' -f 1)

   if [ -n "${id}" ] ; then
      echo "delete digitalocean fw ${id}"
      doctl compute firewall delete ${id}
   fi
   
   doctl compute tag delete ${name}

}

