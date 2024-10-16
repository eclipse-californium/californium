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
# requirements: (see "provider_???.sh" for details)
# - create cloud-provider account
# - download/install cloud-provider's CLI tools
# - upload ssh keys
#
# requirements for Simple Storage Service (S3):
# - install CLI s3cmd (see https://s3tools.org/s3cmd)
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
# - s3cmd (see above)
# - sed
# - cut
# - grep
# - readlink
# - head
# - base64
#
# if readlink is not available, you may export following paths to prevent errors:
# 
# export INCPATH=/path/to/service/cloud-installs
# export SETUPATH=/path/to/service  // with firewall and letsencrypt.sh
# export FAIL2BANPATH=/path/to/service/fail2ban
# export SERVICEPATH=/path/to/service // with cali.service and demo-devices.txt
#
# if head or base64 are not available, you may export SECRET to prevent errors.
#
# The script uses "cali-demo" as service name, and the "cali" as ssh-key-id.
# To change that export "name" and/or "ssh_key_id":
#
# export name=coaps-s3
#

# domain
if [ -z "${domain}" ]  ; then
   domain=$1
   shift
#   echo "Please set the domain name to be used!"
#   echo "export domain=\"my.domain.xyz\""
#   exit 1
fi

echo "Domain: ${domain}"

# Name of cloud VM
if [ -z "${name}" ]  ; then
   export name=cali-demo
fi

# Ensure, your ssh keys are already uploaded to your provider with name "cali"!
# See "provider_???.sh" for some instructions.
if [ -z "${ssh_key_id}" ]  ; then
   export ssh_key_id="cali"
fi

FULLPATH=$(readlink -f $0)

# setup firewall and letsencrypt
if [ -z "${SETUPPATH}" ]  ; then
   SETUPPATH=${FULLPATH%/*/*/*/*}/cf-cloud-demo-server/service
fi

# import "deploy-dev.sh"
if [ -z "${INCPATH}" ]  ; then
   INCPATH=${SETUPPATH}/cloud-installs
fi

# setup service
if [ -z "${SERVICEPATH}" ]  ; then
   SERVICEPATH=${FULLPATH%/*/*}
fi

if [ -z "${cloud_config}" ]  ; then
   export cloud_config=${SERVICEPATH}/cloud-installs/cloud-config-dev.yaml
fi

if [ -z "${s3_cors_json}" ]  ; then
   export s3_cors_json=${SERVICEPATH}/s3-cors.json
fi

if [ -z "${s3_cors_xml}" ]  ; then
   export s3_cors_xml=${SERVICEPATH}/s3-cors.xml
fi

if [ -z "${s3bucket}" ]  ; then
   s3bucket="${name}-${domain}"
   # convert '.' into '-'
   s3bucket=$(echo "${s3bucket}" | sed "s/\./-/g")
fi

echo "S3: ${s3bucket}"

# Version to deploy
: "${CALI_VERSION=4.0.0-SNAPSHOT}"

# ssh login user
: "${user=root}"

run_jobs=0

. $INCPATH/deploy-dev.sh

# generic providers, may be overwritten by cloud specific provider

provider_enable_s3_acl () {
   echo "${provider} ACL already enabled for s3 bucket ${s3bucket}"
}

provider_create_s3_access_keys() {
   echo "create ${provider} access keys for s3 $1"

   sed "s!^\s*bucket\s*=.*!bucket = $1!" ${S3CFG} >${SERVICEPATH}/.s3cfg.e 

   s3_access_key_id=$(grep "access_key" ${SERVICEPATH}/.s3cfg.e | cut -d '=' -f2 | sed 's/^\s*\|\s*$//g')
   s3_access_key_secret=$(grep "secret_key" ${SERVICEPATH}/.s3cfg.e | cut -d '=' -f2 | sed 's/^\s*\|\s*$//g')

   echo "${s3_access_key_id},${s3_access_key_secret}"

   # adjust S3 credentials in users.txt
   sed "s!^\*\.s3=.*!*.s3='${s3_access_key_id}','${s3_access_key_secret}'!" ${SERVICEPATH}/users.txt >${SERVICEPATH}/users.txt.e
   sed -i "s!^\.s3=.*!.s3='${s3_access_key_id}','${s3_access_key_secret}'!g" ${SERVICEPATH}/users.txt.e

}

provider_delete_s3_access_keys() {
   echo "delete ${provider} access keys for s3 $1"
   rm ${SERVICEPATH}/.s3cfg.e 
   rm ${SERVICEPATH}/users.txt.e
}

provider_s3 () {
   case $1 in
      "exo")
         : "${S3CFGPRV=.s3cfg-exo}"
         . ${FULLPATH%/*}/provider-s3-exo.sh
         . ${FULLPATH%/*}/provider-s3cmd.sh
         ;;
      "aws")
         : "${S3CFGPRV=.s3cfg-aws}"
         . ${FULLPATH%/*}/provider-s3-aws.sh
         . ${FULLPATH%/*}/provider-s3cmd.sh
         ;;
      "do")
         : "${S3CFGPRV=.s3cfg-do}"
         . ${FULLPATH%/*}/provider-s3cmd.sh
         ;;
      *)
         echo "Provider \"$1\" unknown! Use: exo|aws|do."
         exit 1
         ;;
   esac

   if [ -e ${SERVICEPATH}/${S3CFGPRV} ] ; then
      S3CFG=${SERVICEPATH}/${S3CFGPRV}
   elif [ -e ~/${S3CFGPRV} ] ; then
      S3CFG=~/${S3CFGPRV}
   elif [ -z ${S3CFG} ] ; then
      echo "Missing ${S3CFGPRV}!"
      exit 1
   fi
}

install_cloud_vm () {
   echo "install ${provider} proxy ${name}"

   provider_s3 ${provider_id}

   install_cloud_vm_base

   # replace dtls graceful restart password
   sed "s!--store-password64=[^\"\t ]*!--store-password64=${SECRET}!" ${SERVICEPATH}/cali.service >${SERVICEPATH}/cali.service.e 
   
   # adjust domain
   sed -i "s!--https-credentials=[^\"\t ]*!--https-credentials=/etc/letsencrypt/live/${domain}!" ${SERVICEPATH}/cali.service.e

   # service (may contain credentials)
   scp ${sshkeys} ${SERVICEPATH}/cali.service.e ${user}@${ip}:/etc/systemd/system/cali.service
   scp ${sshkeys} ${SERVICEPATH}/demo-devices.txt ${user}@${ip}:/home/cali
   scp ${sshkeys} ${SERVICEPATH}/users.txt.e ${user}@${ip}:/home/cali/users.txt
   scp ${sshkeys} ${SERVICEPATH}/configs.txt ${user}@${ip}:/home/cali
   scp ${sshkeys} ${SERVICEPATH}/.s3cfg.e ${user}@${ip}:/home/cali/.s3cfg
   scp ${sshkeys} ${SERVICEPATH}/../target/cf-s3-proxy-server-${CALI_VERSION}.jar ${user}@${ip}:/home/cali/cf-s3-proxy-server-update.jar
   scp ${sshkeys} ${SERVICEPATH}/../src/main/resources/logback.xml ${user}@${ip}:/home/cali

   scp ${sshkeys} ${SERVICEPATH}/permissions.sh ${user}@${ip}:/home/cali

   # create coap ec-key-pair and apply permissions 
   ssh ${sshkeys} ${user}@${ip} "openssl ecparam -genkey -name prime256v1 -noout -out /home/cali/privkey.pem; sh /home/cali/permissions.sh"

   ssh ${sshkeys} ${user}@${ip} "systemctl enable cali"

   ssh ${sshkeys} ${user}@${ip} "systemctl reboot"

   echo "Reboot cloud VM."

   echo "use: ssh${sshkeys} ${user}@${ip} to login!"
}

update_cloud_vm () {
   echo "update ${provider} server ${name}"

   get_ip

   provider_s3 ${provider_id}

   if [ -z "${SECRET}" ]  ; then
      SECRET=$(cat ${SERVICEPATH}/store-password64)     
   fi

   # replace dtls graceful restart password
   sed "s!--store-password64=[^\"\t ]*!--store-password64=${SECRET}!" ${SERVICEPATH}/cali.service >${SERVICEPATH}/cali.service.e 

   # update service 

   scp ${sshkeys} ${SERVICEPATH}/.s3cfg.e ${user}@${ip}:/home/cali/.s3cfg

   scp ${sshkeys} ${SERVICEPATH}/cali.service.e ${user}@${ip}:/etc/systemd/system/cali.service
   scp ${sshkeys} ${SERVICEPATH}/../target/cf-s3-proxy-server-${CALI_VERSION}.jar ${user}@${ip}:/home/cali/cf-s3-proxy-server-update.jar
   scp ${sshkeys} ${SERVICEPATH}/../src/main/resources/logback.xml ${user}@${ip}:/home/cali

   ssh ${sshkeys} ${user}@${ip} "sh /home/cali/permissions.sh; systemctl daemon-reload; systemctl restart cali"

   echo "use: ssh${sshkeys} ${user}@${ip} to login!"
}

update_app () {
   echo "update app ${provider} server ${name}"

   get_ip

   scp ${sshkeys} ${SERVICEPATH}/../target/cf-s3-proxy-server-${CALI_VERSION}.jar ${user}@${ip}:/home/cali/cf-s3-proxy-server-update.jar

   ssh ${sshkeys} ${user}@${ip} "systemctl restart cali"

   echo "use: ssh${sshkeys} ${user}@${ip} to login!"
}


jobs_s3 () {
   provider_s3 ${provider_id}
   case $1 in
      "create-bucket")
         echo "${provider} $1"
         sed "s!>https://domain<!>https://${domain}<!" ${s3_cors_xml} >${s3_cors_xml}.e
         provider_create_s3_bucket
         ;;
      "delete-bucket")
         echo "${provider} $1"
         provider_delete_s3_bucket
         ;;
      "update-app")
         echo "${provider} $1"
         update_app
         ;;
      "create-devdom")
         echo "${provider} $1"
         sed "s!>https://domain<!>https://${domain}<!" ${s3_cors_xml} >${s3_cors_xml}.e
         provider_create_s3_devicedomain_bucket 
         ;;
      "delete-devdom")
         echo "${provider} $1"
         provider_delete_s3_devicedomain_bucket
         ;;
      *)
         jobs $1
         ;;
   esac
}

for JOB in ${JOBS}; do
   jobs_s3 ${JOB}
done

