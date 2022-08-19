#!/bin/sh

#/*******************************************************************************
# * Copyright (c) 2022 Contributors to the Eclipse Foundation.
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
# ******************************************************************************/

source setup.sh

if [ -z "$1" ] ; then
   NUMBER_DEVICES_TO_CREATE=2190
else
   NUMBER_DEVICES_TO_CREATE=$1
fi

if [ -z "$2" ] ; then
   START_DEVICES_TO_CREATE=1
else
   START_DEVICES_TO_CREATE=$2
fi

CREDENTIALS_FILE=loadtest-demo.psk

END_DEVICES_TO_CREATE=$((${START_DEVICES_TO_CREATE} + ${NUMBER_DEVICES_TO_CREATE} - 1))

if [ ${NUMBER_DEVICES_TO_CREATE} -gt 0 ] ; then
  echo "create devices ${START_DEVICES_TO_CREATE} ${END_DEVICES_TO_CREATE}"
  
  rm $CREDENTIALS_FILE
  for j in $(seq ${START_DEVICES_TO_CREATE} ${END_DEVICES_TO_CREATE}) ; do
    i=$( printf 'cali.58%05d' $j)
    echo "create device ${i}"
    secret=$(cat /dev/urandom | head -c15 | base64)
    echo "${i}=${secret}" >> $CREDENTIALS_FILE
    done 
fi


