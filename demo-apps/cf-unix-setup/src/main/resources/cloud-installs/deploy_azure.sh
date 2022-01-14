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
# - active account at https://azure.microsoft.com (please obey the resulting costs!)
# - install https://docs.microsoft.com/cli/azure/install-azure-cli 
#   and configure it
# - copy ssh-public-key to "sshkey" below. Seems to support only "ssh-rsa" keys.
# 
# Adapt the the "vmsize" according your requirements and wanted price.
# See https://azure.microsoft.com/pricing/details/virtual-machines/ and
# run `az vm list-sizes --location <zone>` to see the options.
#
# https://docs.microsoft.com/cli/azure/azure-cli-vm-tutorial
#
# Before executing this script, "az login" may be required to refresh the az login credentials.

name=cali

sshkey="ssh-rsa AAAAB3N???"

zone="westeurope"
vmsize="Standard_B1s"

get_ip() {
   ip=$(az vm show --resource-group ${name}Resources --name ${name} --show-details --query publicIps --output tsv)
   echo "vm-ip: ${ip}"
}

wait_vm_ready() {
   status=$(az vm show --resource-group ${name}Resources --name ${name} --show-details --query powerState --output tsv)
   while [ "${status}" != "VM running" ] ; do
      echo "vm: ${status}, waiting for VM running"
      sleep 10
      status=$(az vm show --resource-group ${name}Resources --name ${name} --show-details --query powerState --output tsv)
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
   echo "create azure server ${name}"

   az group create --name ${name}Resources --location ${zone}

   az sshkey create --resource-group ${name}Resources --name root --public-key "${sshkey}"

   az vm create --resource-group ${name}Resources \
     --name ${name} \
     --image UbuntuLTS \
     --ssh-key-name root \
     --size ${vmsize} \
     --public-ip-sku Standard \
     --custom-data cloud-config.yaml \
     --verbose

   nsg=$(az network nsg list --resource-group ${name}Resources --query [].name --output tsv)
   echo "Network Security Group: ${nsg}, enable coaps"

   az network nsg rule create --resource-group ${name}Resources --name ${name}coaps --nsg-name "${nsg}" \
      --priority 800 --access Allow --protocol Udp --destination-port-ranges 5684

   echo "wait to give vm time to finish the installation!"

   wait_vm_ready

   get_ip

   wait_cloud_init_ready

   echo "use: ssh root@${ip} to login!"

   exit 0
fi

if [ "$1" = "delete" ]  ; then
   echo "delete azure server ${name}"

   get_ip

   az vm delete --resource-group ${name}Resources --name ${name}

   echo "delete azure group"
   az group delete --name ${name}Resources

   echo "Please verify the successful deletion via the Web UI."

   echo "Remove the ssh trust for ${ip} with:"
   echo "ssh-keygen -f ~/.ssh/known_hosts -R \"${ip}\""

   exit 0
fi

echo "usage: (create|delete)"

