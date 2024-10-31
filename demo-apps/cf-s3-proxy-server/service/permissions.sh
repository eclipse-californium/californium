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
# Adjust permission for several configuration files, which may contain credentials

prot () {
  if [ -e "$1" ] ; then
    chmod o-r $1
    chown cali:cali $1
    echo "Protected $1";  
  else
    echo "Missing $1";  
  fi	
}

chmod o-r /etc/systemd/system/cali.service

prot /home/cali/demo-devices.txt
prot /home/cali/fullchain.pem
prot /home/cali/privkey.pem
prot /home/cali/users.txt
prot /home/cali/configs.txt
prot /home/cali/.s3cfg

