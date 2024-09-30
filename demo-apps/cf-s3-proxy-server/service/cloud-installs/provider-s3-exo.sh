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
# create IAM access keys:
# coapproxy: write/read
# web      : write/read
# web-read : read only
#

provider_create_s3_access_keys() {
   echo "create exoscale access keys for s3 $1"

   exo iam role create s3-$1-write --description "S3 $1 read/write" \
       --policy - << POLICY
{
 "default-service-strategy":"deny",
 "services":{
  "sos":{
   "type":"rules","rules":[
    {"action":"deny","expression":"resources.bucket != '$1'"},
    {"action":"allow","expression":"operation == 'head-object'"},
    {"action":"allow","expression":"operation == 'get-object'"},
    {"action":"allow","expression":"operation == 'list-objects'"},
    {"action":"allow","expression":"operation == 'put-object'"},
    {"action":"allow","expression":"operation == 'delete-object'"},
    {"action":"deny","expression":"true"}
   ]
  }
 }
}
POLICY

   s3_access_key=$(exo iam api-key create s3-$1-coapproxy s3-$1-write -O text --output-template '{{ .Key }},{{ .Secret }}')
   s3_proxy_access_key_id=$(echo $s3_access_key | cut -d ',' -f1)
   s3_proxy_access_key_secret=$(echo $s3_access_key | cut -d ',' -f2)
   echo "$s3_proxy_access_key_id $s3_proxy_access_key_secret"

   cat - >${SERVICEPATH}/.s3cfg.e << S3CFG 
[default]
host_base = sos-de-fra-1.exo.io
host_bucket = %(bucket)s.sos-de-fra-1.exo.io
bucket = $1
access_key = ${s3_proxy_access_key_id}
secret_key = ${s3_proxy_access_key_secret}
use_https = true
S3CFG

   if [ -n "$2" ]  ; then
# only for buckets with web access   
      exo iam role create s3-$1-read --description "S3 $1 read only" \
         --policy - << POLICY
{
 "default-service-strategy":"deny",
 "services":{
  "sos":{
   "type":"rules","rules":[
    {"action":"deny","expression":"resources.bucket != '$1'"},
    {"action":"allow","expression":"operation == 'head-object'"},
    {"action":"allow","expression":"operation == 'get-object'"},
    {"action":"allow","expression":"operation == 'list-objects'"},
    {"action":"deny","expression":"true"}
   ]
  }
 }
}
POLICY

      s3_access_key=$(exo iam api-key create s3-$1-webuser s3-$1-read -O text --output-template '{{ .Key }},{{ .Secret }}')
      s3_web_user_access_key_id=$(echo $s3_access_key | cut -d ',' -f1)
      s3_web_user_access_key_secret=$(echo $s3_access_key | cut -d ',' -f2)
      echo "$s3_web_user_access_key_id $s3_web_user_access_key_secret"

      # adjust S3 credentials in users.txt
      sed "s!^\*\.s3=.*!*.s3='${s3_web_user_access_key_id}','${s3_web_user_access_key_secret}'!" ${SERVICEPATH}/users.txt >${SERVICEPATH}/users.txt.e 
   
   fi
}

provider_delete_s3_access_keys() {
   if [ -n "$2" ]  ; then
# only for buckets with web access   
      exo iam api-key delete s3-$1-webuser
      exo iam role delete s3-$1-read   
   fi
   exo iam api-key delete s3-$1-coapproxy
   exo iam role delete s3-$1-write
}

