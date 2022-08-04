#!/bin/sh

#/*******************************************************************************
# * Copyright (c) 2023 Contributors to the Eclipse Foundation.
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
# requirements: (see "provider_???.sh" for details)
# - create cloud-provider account
# - download/install cloud-provider's CLI tools
# - upload ssh keys
#
# This script deploys the local artefacts into the cloud.
# A script to deploy a release will come. 
#
# Each provider script must implement:
# - get_ip                   : returns the ip-address of the cloud-vm ${name} in ${ip}
# - provider_create_cloud_vm : creates a cloud-vm using ${name}, ${ssh_key_id}, and
#                              ${cloud_config} 
# - provider_delete_cloud_vm : deletes cloud-vm ${name}
#
# required sh commands:
# - readlink
#
# if readlink is not available, you may export following paths to prevent errors:
# 
# export INCPATH=/path/to/service/cloud-installs
# export SETUPATH=/path/to/service  // with firewall and letsencrypt.sh
# export FAIL2BANPATH=/path/to/service/fail2ban
# export SERVICEPATH=/path/to/service // with cali.service and demo.psk
#
# The script uses "cali-demo" as service name, and the "cali" as ssh-key-id.
# To change that export "name" and/or "ssh_key_id":
#
# export name=coaps-s3
#
# Required sh commands for do (Digital Ocean) only:
# - grep
# - cut
#

# Name of cloud VM
if [ -z "$name" ]  ; then
   export name=cali-demo
fi

# Ensure, your ssh keys are already uploaded to your provider with name "cali"!
# See "provider_???.sh" for some instructions.
if [ -z "$ssh_key_id" ]  ; then
   export ssh_key_id="cali"
fi

# setup firewall and letsencrypt
if [ -z "${SETUPPATH}" ]  ; then
   SETUPFULLPATH=$(readlink -f $0)
   SETUPPATH=${SETUPFULLPATH%/*/*}
fi

# import "provider_???.sh"
if [ -z "${INCPATH}" ]  ; then
   INCPATH=${SETUPPATH}/cloud-installs
fi

# setup fail2ban
if [ -z "${FAIL2BANPATH}" ]  ; then
   FAIL2BANPATH=${SETUPPATH}/fail2ban
fi

# setup service
if [ -z "${SERVICEPATH}" ]  ; then
   SERVICEPATH=${SETUPPATH}
fi

if [ -z "$cloud_config" ]  ; then
   export cloud_config=${INCPATH}/cloud-config-dev.yaml
fi

# Version to deploy
: "${CALI_VERSION=3.11.0-SNAPSHOT}"

# ssh login user
: "${user=root}"

# run jobs per default
: "${run_jobs=1}"

wait_cloud_init_ready () {
   status=$(ssh -o "StrictHostKeyChecking=accept-new" ${user}@${ip} "cloud-init status")

   while [ "${status}" != "status: done" ] ; do
      echo "cloud-init: ${status}, waiting for done"
      sleep 10
      status=$(ssh -o "StrictHostKeyChecking=accept-new" ${user}@${ip} "cloud-init status")
   done
   echo "cloud-init: ${status}"
}

install_cloud_vm_base () {

   get_ip

   ssh -o "StrictHostKeyChecking=accept-new" ${user}@${ip} "exit"

   # firewall & forward
   scp ${SETUPPATH}/iptables.service ${user}@${ip}:/etc/systemd/system
   scp ${SETUPPATH}/iptables-firewall.sh ${user}@${ip}:/sbin
   ssh ${user}@${ip} "chmod u+x /sbin/iptables-firewall.sh; systemctl enable iptables"

   # let's encrypt
   scp ${SETUPPATH}/letsencrypt.sh ${user}@${ip}:.

   # fail2ban
   scp ${FAIL2BANPATH}/cali2fail.conf ${user}@${ip}:/etc/fail2ban/jail.d
   scp ${FAIL2BANPATH}/calidtls.conf ${user}@${ip}:/etc/fail2ban/filter.d
   scp ${FAIL2BANPATH}/calihttps.conf ${user}@${ip}:/etc/fail2ban/filter.d
   scp ${FAIL2BANPATH}/calilogin.conf ${user}@${ip}:/etc/fail2ban/filter.d

   ssh ${user}@${ip} "su cali -c 'mkdir /home/cali/logs; touch /home/cali/logs/ban.log'"
}

install_cloud_vm () {
   echo "install ${provider} server ${name}"

   install_cloud_vm_base

   # service 
   scp ${SERVICEPATH}/cali.service ${user}@${ip}:/etc/systemd/system
   scp ${SERVICEPATH}/../target/cf-cloud-demo-server-${CALI_VERSION}.jar ${user}@${ip}:/home/cali/cf-cloud-demo-server-update.jar
   scp ${SERVICEPATH}/../src/main/resources/logback.xml ${user}@${ip}:/home/cali

   scp ${SERVICEPATH}/demo.psk ${user}@${ip}:/home/cali

   ssh ${user}@${ip} "systemctl enable cali"

   ssh ${user}@${ip} "systemctl reboot"

   echo "Reboot cloud VM."

   echo "use: ssh ${user}@${ip} to login!"
}

update_cloud_vm () {
   echo "update ${provider} server ${name}"

   get_ip

   # update service 
   scp ${SERVICEPATH}/cali.service ${user}@${ip}:/etc/systemd/system
   scp ${SERVICEPATH}/../target/cf-cloud-demo-server-${CALI_VERSION}.jar ${user}@${ip}:/home/cali/cf-cloud-demo-server-update.jar
   scp ${SERVICEPATH}/../src/main/resources/logback.xml ${user}@${ip}:/home/cali

   ssh ${user}@${ip} "systemctl daemon-reload; systemctl restart cali;"

   echo "use: ssh ${user}@${ip} to login!"
}

login_cloud_vm () {
   echo "login ${provider} server ${name}"

   get_ip

   if [ "${ip}" ]  ; then
      wait_cloud_init_ready

      echo "use: ssh ${user}@${ip} to login!"
   else 
      echo "${name} not available at ${provider}!"
      exit 1
   fi   
}

create_cloud_vm () {
   get_ip

   if [ "${ip}" ]  ; then
      echo "${name} already exists!"
      exit 1
   fi

   provider_create_cloud_vm
}

delete_cloud_vm () {
   get_ip

   provider_delete_cloud_vm

   echo "Please verify the successful deletion via the Web UI to prevent unexpected costs!"

   if [ -n "${ip}" ] ; then
      echo "Remove the ssh trust for ${ip}"
      ssh-keygen -f ~/.ssh/known_hosts -R "${ip}"
   else   
      echo "No IP address found for ${name}."
   fi
}

provider () {
   provider_id=$1
   case $1 in
      "exo")
         provider="ExoScale"
         . $INCPATH/provider-exo.sh
         ;;
      "aws")
         provider="AWS"
         . $INCPATH/provider-aws.sh
         ;;
      "do")
         provider="DigitalOcean"
         . $INCPATH/provider-do.sh
         ;;
      *)
         echo "Provider \"$1\" unknown! Use: exo|aws|do."
         exit 1
      ;;
   esac
}

jobs () {
   echo "${provider} $1"
   case $1 in
      "create")
         create_cloud_vm
         ;;
      "delete")
         delete_cloud_vm
         ;;
     "install")
         install_cloud_vm
         ;;
      "login")
         login_cloud_vm
         ;;
      "update")
         update_cloud_vm
         ;;
      *)
         echo "Job \"$1\" unknown! Use: (create|delete|install|login|update)+"
         exit 1
         ;;
   esac
}

all_jobs () {
   for JOB in ${JOBS}; do
      jobs ${JOB}
   done
}


if [ -z "$1" ]  ; then
   echo "Missing cloud provider. Use: exo|aws|do"
   exit
else
   provider $1
   shift
fi

if [ -z "$1" ]  ; then
   echo "Missing job. Use: (create|delete|install|login|update)+"
   exit
else
   JOBS=$@
fi

if [ ${run_jobs} -eq 1 ] ; then
# skipped, if included
   all_jobs
fi
