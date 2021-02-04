#!/bin/sh

#/*******************************************************************************
# * Copyright (c) 2020 Bosch.IO GmbH and others.
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
# steps to install a californium.jar as unix systemd service 
#
# NOT INTENDED TO BE EXECUTED!
# 
# The single lines may be adjusted and copied for installation! 

# create non-su, non-login user
sudo adduser --system --home /home/cali --disabled-login cali
# move application from current folder
sudo mv cf-plugtest-server-2.6.1.jar /home/cali/
# move service definition from current folder
sudo mv cali.service /etc/systemd/system
# reload service definitions
sudo systemctl daemon-reload
# enable service auto-start
sudo systemctl enable cali
