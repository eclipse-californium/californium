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

sshkey="ssh-rsa AAAAB3N???"

zone="westeurope"
vmsize="Standard_B1s"

if [ "$1" = "create" ]  ; then
   echo "create azure server"

   az group create --name CaliResources --location ${zone}

   az sshkey create --resource-group CaliResources --name root --public-key "${sshkey}"

   az vm create --resource-group CaliResources \
     --name Cali \
     --image UbuntuLTS \
     --ssh-key-name root \
     --size ${vmsize} \
     --public-ip-sku Standard \
     --custom-data cloud-config.yaml \
     --verbose

   nsg=$(az network nsg list --resource-group CaliResources --query [].name --output tsv)
   echo "Network Security Group: ${nsg}, enable coaps"

   az network nsg rule create --resource-group CaliResources --name coaps --nsg-name "${nsg}" \
      --priority 800 --access Allow --protocol Udp --destination-port-ranges 5684

   echo "wait to give vm time to finish the installation!"
   sleep 30

   ip=$(az vm show --resource-group CaliResources --name Cali --show-details --query publicIps --output tsv)

   echo "use: ssh root@${ip} to login!"

   exit 0
fi

if [ "$1" = "delete" ]  ; then
   echo "delete azure server"
   az vm delete --resource-group CaliResources --name Cali

   echo "delete azure group"
   az group delete --name CaliResources

   exit 0
fi

echo "usage: (create|delete)"

