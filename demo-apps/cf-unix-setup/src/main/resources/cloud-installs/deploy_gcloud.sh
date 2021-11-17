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

vmsize="e2-micro"

if [ "$1" = "create" ]  ; then
   echo "create google cloud server"

   gcloud compute firewall-rules create coaps --allow udp:5684 --target-tags=coaps

   zone="europe-west3-a"

   gcloud compute instances create cali \
      --tags="coaps" \
      --zone "${zone}" \
      --machine-type="${vmsize}" \
      --image-family ubuntu-2004-lts \
      --image-project ubuntu-os-cloud \
      --metadata-from-file user-data=cloud-config.yaml

   echo "wait to give vm time to finish the installation!"
   sleep 30 

   ip=$(gcloud compute instances describe cali --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

   echo "use: ssh root@${ip} to login!"

   exit 0
fi

if [ "$1" = "delete" ]  ; then
   echo "delete google cloud server"

   gcloud compute instances delete cali
   gcloud compute firewall-rules delete coaps

   exit 0
fi

echo "usage: (create|delete)"

