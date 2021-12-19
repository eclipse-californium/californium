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
# edit /var/snap/microk8s/current/args/kubectl-env to load ~/.kube/config
#
# Replace <cloud-registry> and <cloud-context> with your values.

echo "deploy to cloud"

export BUILD_FILE=cf-cloud-build
export REGISTRY=<cloud-registry>

# export KUBECTL=??? ; default microk8s.kubectl
# export KUBECTL_NAMESPACE=??? ; default cali
export KUBECTL_CONTEXT="--context=<cloud-context>"
# export K8S_SERVICE=??? ; default k8s

if [ ! -d "service" ] ; then
   if [ -d "../service" ] ; then
      cd ..
   fi
fi

sh ./service/deploy_k8s.sh $@

