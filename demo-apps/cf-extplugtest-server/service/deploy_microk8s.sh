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

# build cf-extplugtest-server jar ahead using
# mvn clean install

if [ ! -d "target" ] ; then
   if [ -d "../target" ] ; then
      cd ..
   fi
fi

: "${VERSION_FILE:=cf-extserver-update-version}"

CONTAINER=cf-extserver-jdk11-slim:2.6.0

if [ "$1" = "install" ]  ; then
	echo "install ${CONTAINER} to microk8s using namespace cali"
	echo "1" > ${VERSION_FILE}
elif [ "$1" = "update" ]  ; then
	if [ -z "$2" ]  ; then
	     UPDATE_VERSION=$(tail -1 ${VERSION_FILE})	
	else 
	    UPDATE_VERSION=$2
	fi
	echo "$(expr ${UPDATE_VERSION} + 1)" > ${VERSION_FILE}
	CONTAINER="${CONTAINER}.${UPDATE_VERSION}"
	echo "update ${CONTAINER} to microk8s using namespace cali"
else
	echo "either use \"install\" or \"update\""
	exit -1
fi

# default local container registry of microk8s
: "${REGISTRY:=localhost:32000}"

# default microk8s kubectl context (local)
: "${KUBECTL_CONTEXT:=}"

#KUBECTL_CONTEXT="--insecure-skip-tls-verify --context=???"

# build container
docker build . -t ${REGISTRY}/${CONTAINER} -f service/Dockerfile

# push to container registry
docker push ${REGISTRY}/${CONTAINER}

if [ "$1" = "install" ]  ; then
	# namespace
	microk8s.kubectl $KUBECTL_CONTEXT delete namespace cali
	microk8s.kubectl $KUBECTL_CONTEXT create namespace cali

	token=$(microk8s kubectl $KUBECTL_CONTEXT -n kube-system get secret | grep default-token | cut -d " " -f1)
	token=$(microk8s kubectl $KUBECTL_CONTEXT -n kube-system describe secret $token | grep token: )
	token=$(echo $token | cut -d " " -f2 )

	echo $token

	# random secret
	secret=$(cat /dev/urandom | head -c32 | base64)

	microk8s.kubectl $KUBECTL_CONTEXT -n cali create secret generic cf-extserver-config \
	  --from-literal=kubectl_token="$token" \
	  --from-literal=kubectl_host="https://10.152.183.1" \
	  --from-literal=kubectl_namespace="cali" \
	  --from-literal=kubectl_selector="app%3Dcf-extserver"\
	  --from-literal=dtls_cid_mgmt_identity="cid-cluster-manager"\
	  --from-literal=dtls_cid_mgmt_secret_base64="$secret"
	  
	# deploy
	microk8s.kubectl $KUBECTL_CONTEXT -n cali apply -f service/k8s.yaml
	microk8s.kubectl $KUBECTL_CONTEXT -n cali patch statefulset cf-extserver --type='json' -p='[{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value":"'${REGISTRY}/${CONTAINER}'"}]'
	echo "installed"
	
elif [ "$1" = "update" ]  ; then

	# update
	microk8s.kubectl $KUBECTL_CONTEXT -n cali patch statefulset cf-extserver --type='json' -p='[{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value":"'${REGISTRY}/${CONTAINER}'"}]'

	echo "updated"

fi
