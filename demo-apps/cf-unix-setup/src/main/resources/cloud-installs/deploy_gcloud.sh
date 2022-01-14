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
# requirements (still not complete):
# - active account at https://cloud.google.com (please obey the resulting costs!)
# - install https://cloud.google.com/sdk/docs/quickstart and configure it
# - gcloud services enable compute.googleapis.com
# - upload your ssh-key to https://console.cloud.google.com/compute/metadata/sshKeys
#   use "root" as comment/last part, "<key-type> <public key> root" 
#
# Adapt the the "vmsize" according your requirements and wanted price.
# See https://cloud.google.com/compute, 
# https://cloud.google.com/compute/docs/machine-types
# and https://cloud.google.com/compute/vm-instance-pricing
# gcloud compute machine-types list

name=cali
vmsize="e2-micro"

get_ip() {
   ip=$(gcloud compute instances describe ${name} --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
   echo "vm-ip: ${ip}"
}

wait_vm_ready() {
   status=$(gcloud compute instances describe ${name} --format='get(status)')
   while [ "${status}" != "RUNNING" ] ; do
      echo "vm: ${status}, waiting for RUNNING"
      sleep 10
      status=$(gcloud compute instances describe ${name} --format='get(status)')
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
   echo "create google cloud server ${name}"

   gcloud compute firewall-rules create ${name}-coaps --allow udp:5684 --target-tags=${name}-coaps

   zone="europe-west3-a"

   gcloud compute instances create ${name} \
      --tags="${name}-coaps" \
      --zone "${zone}" \
      --machine-type="${vmsize}" \
      --image-family ubuntu-2004-lts \
      --image-project ubuntu-os-cloud \
      --metadata-from-file user-data=cloud-config.yaml

   echo "wait to give vm time to finish the installation!"

   wait_vm_ready

   get_ip

   wait_cloud_init_ready

   echo "use: ssh root@${ip} to login!"

   exit 0
fi

if [ "$1" = "delete" ]  ; then
   echo "delete google cloud server ${name}"

   get_ip

   gcloud compute instances delete ${name}
   gcloud compute firewall-rules delete ${name}-coaps

   echo "Please verify the successful deletion via the Web UI."

   echo "Remove the ssh trust for ${ip} with:"
   echo "ssh-keygen -f ~/.ssh/known_hosts -R \"${ip}\""

   exit 0
fi

echo "usage: (create|delete)"
