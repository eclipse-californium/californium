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
# requires: docker, kubectl, head, base64, grep, cut

if [ ! -d "target" ] ; then
	if [ -d "../target" ] ; then
		cd ..
	fi
fi

# file to keep the latest installed build number
: "${BUILD_FILE:=cf-extserver-build}"

# default local container registry of microk8s
: "${REGISTRY:=localhost:32000}"

# default microk8s kubectl
: "${KUBECTL:=microk8s.kubectl}"

# default (microk8s) kubectl namespace cali
: "${KUBECTL_NAMESPACE:=cali}"

# default kubectl context (local)
# e.g. KUBECTL_CONTEXT="--insecure-skip-tls-verify --context=???"
: "${KUBECTL_CONTEXT:=}"

CONTAINER=cf-extserver-jdk11-slim
VERSION=3.0.0

if [ "$1" = "install" ]  ; then
	CONTAINER_VERSION="${CONTAINER}:${VERSION}"
	echo "install ${CONTAINER_VERSION} to microk8s using namespace ${KUBECTL_NAMESPACE}"
	BUILD_NUMBER=0
elif [ "$1" = "update" ] || [ "$1" = "update0" ] ; then
	if [ -z "$2" ]  ; then
		BUILD_NUMBER=$(( $(tail -1 ${BUILD_FILE}) + 1))	
	else 
		BUILD_NUMBER=$2
	fi
	VERSION="${VERSION}.${BUILD_NUMBER}"
	CONTAINER_VERSION="${CONTAINER}:${VERSION}"
	echo "update ${CONTAINER} to microk8s using namespace ${KUBECTL_NAMESPACE}"
else
	echo "either use \"install\", \"update\" (image), or \"update0\" (green/blue)"
	exit -1
fi

# keep for next update without provided build-number
echo "${BUILD_NUMBER}" > ${BUILD_FILE}
# save it for access inside the container
echo "${BUILD_NUMBER}" > service/build

# build container
docker build . -t ${REGISTRY}/${CONTAINER_VERSION} -f service/Dockerfile

# push to container registry
docker push ${REGISTRY}/${CONTAINER_VERSION}

SHA=$(docker pull ${REGISTRY}/${CONTAINER_VERSION} | grep Digest: | cut -d ' ' -f 2)
IMAGE_SHA="${REGISTRY}/${CONTAINER}@${SHA}"

echo "Image: ${IMAGE_SHA}"

# get current replicas counter.
# parameter: name of statefulset, e.g.
#
# get_count cf-extserver-a
#
get_count() {
	count=$(${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} get statefulset $1 --output='jsonpath={.status.currentReplicas}' --ignore-not-found)
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
	ready=$(${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} get statefulset $1 --output='jsonpath={.status.readyReplicas}' --ignore-not-found)
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
	${KUBECTL} ${KUBECTL_CONTEXT} delete namespace ${KUBECTL_NAMESPACE} --ignore-not-found
	${KUBECTL} ${KUBECTL_CONTEXT} create namespace ${KUBECTL_NAMESPACE}

	# random secret
	secret=$(cat /dev/urandom | head -c32 | base64)

	# use empty token in order to read the token from the service account 
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} create secret generic cf-extserver-config \
	  --from-file=https_client_cert.pem="service/client.pem" \
	  --from-file=https_client_trust.pem="service/caTrustStore.pem" \
	  --from-file=https_server_cert.pem="service/server.pem" \
	  --from-file=https_server_trust.pem="service/caTrustStore.pem" \
	  --from-literal=kubectl_token="" \
	  --from-literal=kubectl_selector_label="controller-revision-hash" \
	  --from-literal=dtls_cid_mgmt_identity="cid-cluster-manager" \
	  --from-literal=dtls_cid_mgmt_secret_base64="${secret}"
	  
	# deploy
	# create role and binding in order to grant access for the service account to list and read pods  
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} apply -f service/k8s_rbac.yaml
	# create statefulset
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} apply -f service/k8sa.yaml
	# apply the image
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} patch statefulset cf-extserver-a --type='json' -p='[{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value":"'${IMAGE_SHA}'"}]'
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} apply -f service/k8s.yaml
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

	# update the image
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} patch statefulset cf-extserver-a --type='json' -p='[{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value":"'${IMAGE_SHA}'"}]'

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

	get_count cf-extserver-${old_deployment}
	count=$?
	echo "${count} replicas"

	# updateb
	# remove statefulset, if left over 
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} delete --ignore-not-found statefulset cf-extserver-${new_deployment}
	# label old set
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} label pods restore=true -l app=cf-extserver
	# create new statefulset
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} apply -f service/k8s${new_deployment}.yaml
	# apply the current number of replicas
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} patch statefulset cf-extserver-${new_deployment} --type='json' -p='[{"op": "replace", "path": "/spec/replicas", "value":'${count}'}, {"op": "replace", "path": "/spec/template/metadata/labels/initialDtlsClusterNodes", "value":"'${count}'"}]'

	# apply the image
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} patch statefulset cf-extserver-${new_deployment} --type='json' -p='[{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value":"'${IMAGE_SHA}'"}]'

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

	# remove the old statefulset 
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} delete statefulset cf-extserver-${old_deployment}

	elapse=$(($(date +%s) - $start))

	echo " ${elapse} secs. ${new_deployment} updated. $(date)"

fi

