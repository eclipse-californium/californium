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
# - install s3cmd


provider_create_s3_bucket() {
   echo "S3cmd create bucket ${s3bucket}"

   provider_create_s3_access_keys ${s3bucket} "web"

   s3cmd -c $S3CFG mb s3://${s3bucket}
   
   provider_enable_s3_acl
      
   s3cmd -c $S3CFG setacl --acl-private s3://${s3bucket}
   s3cmd -c $S3CFG setcors ${s3_cors_xml}.e s3://${s3bucket}
   
   s3cmd -c $S3CFG put --acl-public -m "text/javascript; charset=utf-8" --add-header "Cache-Control:no-cache" \
      ${SERVICEPATH}/../src/main/resources/app.js s3://${s3bucket}/app.js
      
   s3cmd -c $S3CFG put --acl-public -m "text/css; charset=utf-8" --add-header "Cache-Control:no-cache" \
      ${SERVICEPATH}/../src/main/resources/stylesheet.css s3://${s3bucket}/stylesheet.css

   s3cmd -c $S3CFG put --acl-public -m "text/javascript; charset=utf-8" --add-header "Cache-Control:no-cache" \
      ${SERVICEPATH}/../src/main/resources/appv2.js s3://${s3bucket}/appv2.js

   s3cmd -c $S3CFG put -m "image/svg+xml" ${SERVICEPATH}/../docs/coap.svg s3://${s3bucket}/logo.svg

}


provider_delete_s3_bucket() {
   echo "S3cmd delete bucket ${s3bucket}"
   
   s3cmd -c $S3CFG rb -rf s3://${s3bucket}

   provider_delete_s3_access_keys ${s3bucket} "web"
}

provider_create_s3_devicedomain_bucket() {
   if [ -z "${devicedomain}" ]  ; then
      echo "misssing \$devicedomain!"
      echo "please export devicedomain=<device-domain>"
      exit
   fi

   echo "S3cmd create device-domain buckets ${devicedomain}"
   mkdir ${SERVICEPATH}/${devicedomain}

# backup S3 credentials
   cp ${SERVICEPATH}/.s3cfg.e ${SERVICEPATH}/.s3cfg.e.bak
   cp ${SERVICEPATH}/users.txt.e ${SERVICEPATH}/users.txt.e.bak
	
   provider_create_s3_access_keys ${devicedomain} "web"

   cp ${SERVICEPATH}/.s3cfg.e ${SERVICEPATH}/${devicedomain}/.s3cfg
   cp ${SERVICEPATH}/users.txt.e ${SERVICEPATH}/${devicedomain}/users.txt

   s3cmd -c $S3CFG mb s3://${devicedomain}         
   s3cmd -c $S3CFG setacl --acl-private s3://${devicedomain}
   s3cmd -c $S3CFG setcors ${s3_cors_xml}.e s3://${devicedomain}

   s3mgmt="${devicedomain}-mgmt"

   provider_create_s3_access_keys ${s3mgmt}
   cp ${SERVICEPATH}/.s3cfg.e ${SERVICEPATH}/${devicedomain}/.s3cfg-mgmt
   
   s3cmd -c $S3CFG mb s3://${s3mgmt}         
   s3cmd -c $S3CFG setacl --acl-private s3://${s3mgmt}
   
# restore S3 credentials
   mv ${SERVICEPATH}/.s3cfg.e.bak ${SERVICEPATH}/.s3cfg.e
   mv ${SERVICEPATH}/users.txt.e.bak ${SERVICEPATH}/users.txt.e

# create domains section
   date=`date`
   echo "# ${date}" >${SERVICEPATH}/${devicedomain}/domains.txt
   echo "" >> ${SERVICEPATH}/${devicedomain}/domains.txt
   
   sed "s!^\[\s*default\s*\]\$![${devicedomain}.data\]!" ${SERVICEPATH}/${devicedomain}/.s3cfg >>${SERVICEPATH}/${devicedomain}/domains.txt

   echo "concurrency = 400" >> ${SERVICEPATH}/${devicedomain}/domains.txt
   echo "" >> ${SERVICEPATH}/${devicedomain}/domains.txt
	    
   sed "s!^\[\s*default\s*\]\$![${devicedomain}.management\]!" ${SERVICEPATH}/${devicedomain}/.s3cfg-mgmt >>${SERVICEPATH}/${devicedomain}/domains.txt

   echo "" >> ${SERVICEPATH}/${devicedomain}/domains.txt

   echo "device_store = devices.txt" >> ${SERVICEPATH}/${devicedomain}/domains.txt
   echo "config_store = configs.txt" >> ${SERVICEPATH}/${devicedomain}/domains.txt
   echo "user_store = users.txt" >> ${SERVICEPATH}/${devicedomain}/domains.txt
}

provider_delete_s3_devicedomain_bucket() {
   if [ -z "${devicedomain}" ]  ; then
      echo "misssing \$devicedomain!"
      echo "please export devicedomain=<device-domain>"
      exit
   fi
   echo "S3cmd delete device-domain buckets ${devicedomain}"
   
   s3cmd -c $S3CFG rb -rf s3://${devicedomain}

   provider_delete_s3_access_keys ${devicedomain} "web" 

   s3mgmt="${devicedomain}-mgmt"

   s3cmd -c $S3CFG rb -rf s3://${s3mgmt}

   provider_delete_s3_access_keys ${s3mgmt}
   
   rm -rf  ${SERVICEPATH}/${devicedomain}
}

