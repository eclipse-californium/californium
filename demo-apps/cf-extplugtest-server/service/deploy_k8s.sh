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

# default kubectl, use "export KUBECTL=microk8s.kubectl" for microk8s
: "${KUBECTL:=kubectl}"

# default (microk8s) kubectl namespace cali
: "${KUBECTL_NAMESPACE:=cali}"

if [ "${KUBECTL_SVC_HOST}" = "<ip>" ] ; then
   KUBECTL_SVC_HOST=$(${KUBECTL} ${KUBECTL_CONTEXT} get svc kubernetes -o='jsonpath={.spec.clusterIP}')
fi

# default k8s service
: "${KUBECTL_SVC_HOST:=kubernetes.default.svc}"

# default kubectl context (local)
# e.g. KUBECTL_CONTEXT="--context=???" or KUBECTL_CONTEXT="--kubeconfig=???" 
: "${KUBECTL_CONTEXT:=}"

# default k8s service yaml
: "${K8S_SERVICE:=k8s.yaml}"

# default k8s type
: "${K8S_TYPE:=statefulset}"

# default k8s component
: "${K8S_COMPONENT:=k8s_${K8S_TYPE}}"

# default dockerfile
: "${DOCKERFILE:=service/Dockerfile}"

CONTAINER=cf-extserver-jdk11-slim
VERSION=3.11.0

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
docker build . -t ${REGISTRY}/${CONTAINER_VERSION} -f ${DOCKERFILE}

# push to container registry
docker push ${REGISTRY}/${CONTAINER_VERSION}

SHA=$(docker pull ${REGISTRY}/${CONTAINER_VERSION} | grep Digest: | cut -d ' ' -f 2)
IMAGE_SHA="${REGISTRY}/${CONTAINER}@${SHA}"

echo "Image: ${IMAGE_SHA}"

count=`${KUBECTL} ${KUBECTL_CONTEXT} get nodes -o name | wc -l`
echo "${count} nodes found"

if [ "${K8S_TYPE}" = "statefulset" ] ; then
  # default number of replicase
  : "${K8S_REPLICAS:=${count}}"
else
  # default number of replicase
  : "${K8S_REPLICAS:=1}"
fi

echo "Use ${K8S_REPLICAS} replicas"

# get current replicas counter.
# parameter: name of statefulset, e.g.
#
# get_count cf-extserver-a
#
get_count() {
	count=$(${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} get ${K8S_TYPE} $1 \
		--output='jsonpath={.status.currentReplicas}' --ignore-not-found)
	if [ "$count" = "" ]  ; then
		# deployments doesn't have currentReplicas
		return ${K8S_REPLICAS}
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
	ready=$(${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} get ${K8S_TYPE} $1 \
		--output='jsonpath={.status.readyReplicas}' --ignore-not-found)
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
	echo "$1 : ${ready} of ${count}"
	if [ $ready -eq $count ] && [ $count -gt 0 ] ; then
		return 1
	fi
	return 0
}

if [ "$1" = "install" ] ; then

	echo "k8s svc: ${KUBECTL_SVC_HOST}"

	# namespace
	${KUBECTL} ${KUBECTL_CONTEXT} delete namespace ${KUBECTL_NAMESPACE} --ignore-not-found
	${KUBECTL} ${KUBECTL_CONTEXT} create namespace ${KUBECTL_NAMESPACE}

	# random secret
	secret=$(cat /dev/urandom | head -c32 | base64)

	# use empty token in order to read the token from the service account 
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} create secret generic \
	  cf-extserver-config \
	  --from-file=https_client_cert.pem="service/client.pem" \
	  --from-file=https_client_trust.pem="service/caTrustStore.pem" \
	  --from-file=https_server_cert.pem="service/server.pem" \
	  --from-file=https_server_trust.pem="service/caTrustStore.pem" \
	  --from-literal=kubectl_host="${KUBECTL_SVC_HOST}" \
	  --from-literal=kubectl_token="" \
	  --from-literal=kubectl_restore_selector_label="app" \
	  --from-literal=kubectl_selector_label="controller-revision-hash" \
	  --from-literal=dtls_cid_mgmt_identity="cid-cluster-manager" \
	  --from-literal=dtls_cid_mgmt_secret_base64="${secret}"

	# container registry
	if [ -n "${KUBECTL_DOCKER_CREDENTIALS}" ] ; then
		${KUBECTL} ${KUBECTL_CONTEXT} create secret docker-registry regcred -n cali \
		  ${KUBECTL_DOCKER_CREDENTIALS}	  
	fi

	# deploy
	# create role and binding in order to grant access for the service account to list and read pods  
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} apply -f service/k8s_rbac.yaml

	if [ -s "service/k8s_limits.yaml" ] ; then
		# create default resource limits
		${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} apply -f service/k8s_limits.yaml
	fi

	if [ "${K8S_TYPE}" = "statefulset" ] ; then
	  # create statefulset
	  ${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} apply -f service/${K8S_COMPONENT}_a.yaml
	  # apply the current number of replicas
	  ${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} patch ${K8S_TYPE} cf-extserver-a --type='json' \
		-p='[{"op": "replace", "path": "/spec/replicas", "value":'${K8S_REPLICAS}'}, {"op": "replace", "path": "/spec/template/metadata/labels/initialDtlsClusterNodes", "value":"'${K8S_REPLICAS}'"}]'
	else
	  # create deployment
	  ${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} apply -f service/${K8S_COMPONENT}.yaml
	fi
	# apply the image
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} set image ${K8S_TYPE} cf-extserver-a cf-extserver="${IMAGE_SHA}"

	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} apply -f service/${K8S_SERVICE}
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
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} set image ${K8S_TYPE} cf-extserver-a cf-extserver="${IMAGE_SHA}"

	echo "updated"

elif [ "$1" = "update0" ] && [ "${K8S_TYPE}" = "statefulset" ] ; then
	# green/blue for statefulset
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
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} delete --ignore-not-found ${K8S_TYPE} cf-extserver-${new_deployment}
	# label old set
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} label pods restore=true -l app=cf-extserver
	# create new statefulset
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} apply -f service/${K8S_COMPONENT}_${new_deployment}.yaml
	# apply the current number of replicas
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} patch ${K8S_TYPE} cf-extserver-${new_deployment} --type='json' \
		-p='[{"op": "replace", "path": "/spec/replicas", "value":'${count}'}, {"op": "replace", "path": "/spec/template/metadata/labels/initialDtlsClusterNodes", "value":"'${count}'"}]'

	# apply the image
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} set image ${K8S_TYPE} cf-extserver-${new_deployment} cf-extserver="${IMAGE_SHA}"

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
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} delete ${K8S_TYPE} cf-extserver-${old_deployment}

	elapse=$(($(date +%s) - $start))

	echo " ${elapse} secs. ${new_deployment} updated. $(date)"

elif [ "$1" = "update0" ] ; then
	# green/blue for deployments

	# check, if current deployment is ready
	check_ready cf-extserver-a
	if [ $? -ne 1 ] ; then
		echo "current deployment doesn't report ready, ... cancel update"
		exit 1
	fi

	echo "current deployment reports ready, start update"

	# label old pod
	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} label pods restore=true -l app=cf-extserver

	${KUBECTL} ${KUBECTL_CONTEXT} -n ${KUBECTL_NAMESPACE} set image ${K8S_TYPE} cf-extserver-a cf-extserver="${IMAGE_SHA}"

fi

