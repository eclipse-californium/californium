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
#
# requires: docker, kubectl, grep, cut, head, base64

if [ ! -d "target" ] ; then
	if [ -d "../target" ] ; then
		cd ..
	fi
fi

: "${VERSION_FILE:=cf-extserver-update-version}"

CONTAINER=cf-extserver-jdk11-slim:3.0.0

if [ "$1" = "install" ]  ; then
	echo "install ${CONTAINER} to microk8s using namespace cali"
	echo "1" > ${VERSION_FILE}
elif [ "$1" = "update" ] || [ "$1" = "update0" ] ; then
	if [ -z "$2" ]  ; then
		UPDATE_VERSION=$(tail -1 ${VERSION_FILE})	
	else 
		UPDATE_VERSION=$2
	fi
	echo "$(expr ${UPDATE_VERSION} + 1)" > ${VERSION_FILE}
	CONTAINER="${CONTAINER}.${UPDATE_VERSION}"
	echo "update ${CONTAINER} to microk8s using namespace cali"
else
	echo "either use \"install\",  \"update\", or \"update0\""
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

# get current replicas counter.
# parameter: name of statefulset, e.g.
#
# get_count cf-extserver-a
#
get_count() {
	count=$(microk8s.kubectl $KUBECTL_CONTEXT -n cali get statefulset $1 -o custom-columns=READY:.status.currentReplicas --ignore-not-found --no-headers)
	if [ "$count" = "" ]  ; then
		return 0
	fi
	if [ "$count" = "<none>" ]  ; then
		return 0
	fi
	return $count
}

# get ready replicas counter.
# parameter: name of statefulset, e.g.
#
# get_ready cf-extserver-a
#
get_ready() {
	ready=$(microk8s.kubectl $KUBECTL_CONTEXT -n cali get statefulset $1 -o custom-columns=READY:.status.readyReplicas --ignore-not-found --no-headers)
	if [ "$ready" = "" ] ; then
		return 0
	fi
	if [ "$ready" = "<none>" ] ; then
		return 0
	fi
	return $ready
}

# check, if all replicas are ready.
# parameter: name of statefulset, e.g.
#
# check_ready cf-extserver-a
#
check_ready() {
	get_count $1
	count=$?
	get_ready $1
	ready=$?
#	echo "$1 : ${ready} of ${count}"
	if [ $ready -eq $count ] && [ $count -gt 0 ] ; then
		return 1
	fi
	return 0
}

if [ "$1" = "install" ] ; then
	# namespace
	microk8s.kubectl $KUBECTL_CONTEXT delete namespace cali --ignore-not-found
	microk8s.kubectl $KUBECTL_CONTEXT create namespace cali

	token_id=$(microk8s kubectl $KUBECTL_CONTEXT -n kube-system get secret | grep default-token | cut -d " " -f1)
	token=$(microk8s.kubectl $KUBECTL_CONTEXT -n kube-system get secret $token_id -o custom-columns=TOKEN:.data.token --no-headers | base64 -d)

	echo $token

	# random secret
	secret=$(cat /dev/urandom | head -c32 | base64)

	microk8s.kubectl $KUBECTL_CONTEXT -n cali create secret generic cf-extserver-config \
	  --from-file=https_client_cert.pem="service/client.pem" \
	  --from-file=https_client_trust.pem="service/caTrustStore.pem" \
	  --from-file=https_server_cert.pem="service/server.pem" \
	  --from-file=https_server_trust.pem="service/caTrustStore.pem" \
	  --from-literal=kubectl_token="$token" \
	  --from-literal=kubectl_host="https://10.152.183.1" \
	  --from-literal=kubectl_namespace="cali" \
	  --from-literal=kubectl_selector_label="controller-revision-hash" \
	  --from-literal=dtls_cid_mgmt_identity="cid-cluster-manager" \
	  --from-literal=dtls_cid_mgmt_secret_base64="$secret"
	  
	# deploy
	microk8s.kubectl $KUBECTL_CONTEXT -n cali apply -f service/k8sa.yaml
	microk8s.kubectl $KUBECTL_CONTEXT -n cali patch statefulset cf-extserver-a --type='json' -p='[{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value":"'${REGISTRY}/${CONTAINER}'"}]'
	microk8s.kubectl $KUBECTL_CONTEXT -n cali apply -f service/k8s.yaml
	echo "installed"

	start=$(date +%s)
	elapse=0
	get_count cf-extserver-a
	count=$?
	get_ready cf-extserver-a
	ready=$?
	while [ $count -gt $ready ]; do
		echo " ${elapse} secs. ${ready} of ${count} ready"
		sleep 2
		elapse=$(($(date +%s) - $start))
		get_ready cf-extserver-a
		ready=$?
	done
	echo " ${elapse} secs. ${ready} of ${count} ready"
	echo " installation ready. $(date)"

elif [ "$1" = "update" ] ; then

	# update
	microk8s.kubectl $KUBECTL_CONTEXT -n cali patch statefulset cf-extserver-a --type='json' -p='[{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value":"'${REGISTRY}/${CONTAINER}'"}]'

	echo "updated"

elif [ "$1" = "update0" ] ; then

	old_deployment=a
	new_deployment=b
	# check, if a is ready
	check_ready cf-extserver-$old_deployment
	if [ $? -ne 1 ] ; then
		old_deployment=b
		new_deployment=a
		check_ready cf-extserver-$old_deployment
		if [ $? -ne 1 ] ; then
			echo "neither a nor b reports ready, ... cancel update"
			exit 1
		fi
	fi

	echo "${old_deployment} reports ready, start update ${new_deployment}"

	# updateb
	microk8s.kubectl $KUBECTL_CONTEXT -n cali delete --ignore-not-found statefulset cf-extserver-${new_deployment}
	microk8s.kubectl $KUBECTL_CONTEXT -n cali label pods restore=true -l app=cf-extserver
	microk8s.kubectl $KUBECTL_CONTEXT -n cali apply -f service/k8s${new_deployment}.yaml
	microk8s.kubectl $KUBECTL_CONTEXT -n cali patch statefulset cf-extserver-${new_deployment} --type='json' -p='[{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value":"'${REGISTRY}/${CONTAINER}'"}]'

	start=$(date +%s)
	elapse=0
	get_count cf-extserver-${new_deployment}
	count=$?
	get_ready cf-extserver-${new_deployment}
	new_ready=$?
	get_ready cf-extserver-${old_deployment}
	old_ready=$?
	while [ $old_ready -gt 0 ] || [ $new_ready -lt $count ] ; do
		echo " ${elapse} secs. ${old_deployment} reports ${old_ready}, ${new_deployment} reports ${new_ready} of ${count} ready."
		sleep 2
		elapse=$(($(date +%s) - $start))
		get_count cf-extserver-${new_deployment}
		count=$?
		get_ready cf-extserver-${new_deployment}
		new_ready=$?
		get_ready cf-extserver-${old_deployment}
		old_ready=$?
	done

	echo " ${elapse} secs. ${old_deployment} reports ${old_ready}, ${new_deployment} reports ${new_ready} of ${count} ready."

	microk8s.kubectl $KUBECTL_CONTEXT -n cali delete statefulset cf-extserver-${old_deployment}

	elapse=$(($(date +%s) - $start))

	echo " ${elapse} secs. ${new_deployment} updated. $(date)"

fi

