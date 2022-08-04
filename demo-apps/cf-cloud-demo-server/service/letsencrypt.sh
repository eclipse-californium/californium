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
# Adjust permission for let's encrypt https x509 credentials.
#
# See: https://eff-certbot.readthedocs.io/en/stable/using.html#where-are-my-certificates
#
# Requirements:
# - install certbot (see https://certbot.eff.org/instructions?ws=other&os=ubuntufocal)
# - request certificate for <domain>
#   certbot certonly --standalone --key-type ecdsa --elliptic-curve secp256r1 -d <domain>
#
# Usage: ./letsencrypt.sh <domain>

if [ -z "$1" ]  ; then
     echo "Missing domain!"
     exit
fi


letsencrypt=/etc/letsencrypt

if [ ! -d "${letsencrypt}/live/$1" ]; then
   echo "Request x509 certificate for $1"
   certbot certonly --standalone --key-type ecdsa --elliptic-curve secp256r1 -d $1
   if [ ! -d "${letsencrypt}/live/$1" ]; then
      echo "Missing credentials for $1"
      exit 1   
   fi
fi

echo "Adjust file-system permissions for let's encrypt credentials"

chmod go+rx ${letsencrypt}/live

if [ -d "${letsencrypt}/archive" ]; then
   chmod go+rx ${letsencrypt}/archive
   if [ -d "${letsencrypt}/archive/$1" ]; then
      echo "Add read grants for group cali"
      chmod g+r ${letsencrypt}/archive/$1/privkey1.pem
      chown root:cali ${letsencrypt}/archive/$1/privkey1.pem
   fi
else
   echo "Missing credentials archive for $1"
   exit 1   
fi

service=/etc/systemd/system/cali.service
if [ -f "${service}" ]; then
   echo "Configure cali.service to use let's encrypt credentials"
   sed -i "s!--https-credentials=[^\"\t ]*!--https-credentials=/etc/letsencrypt/live/$1!" ${service}
   grep -- "--https-credentials=" ${service}
   chmod o-r ${service}
   echo "Restart cali.service with let's encrypt credentials"
   systemctl daemon-reload
   systemctl restart cali
fi

