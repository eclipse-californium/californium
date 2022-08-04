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
# requirements:
# 
# - activate account at https://portal.aws.amazon.com/billing/signup (please obey the resulting costs!)
# - follow https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html
# -   Create an IAM user account https://docs.aws.amazon.com/cli/latest/userguide/getting-started-prereqs.html#getting-started-prereqs-iam
# -   Create an access key ID and secret access key https://docs.aws.amazon.com/cli/latest/userguide/getting-started-prereqs.html#getting-started-prereqs-keys
# -   install awscli2 https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
#     and configure it https://docs.aws.amazon.com/cli/latest/userguide/getting-started-quickstart.html
# - upload your ssh-key (either rsa or ed25519) using the ec2 console using the name "cali" or 
#      copy a different used name to "ssh_key_id" below.
#
# Adapt the the "vmsize" according your requirements and wanted price.
# See https://aws.amazon.com/ec2/pricing/
#

vmsize="t2.micro"
vmimage="ubuntu/images/hvm-ssd/*22.04*amd64*server*"

get_ami() {
   echo "AMI: " $(aws ec2 describe-images --filters "Name=name,Values=${vmimage}" --owner amazon --query "sort_by(Images, &CreationDate)[-1].Name")
   ami_id=$(aws ec2 describe-images --filters "Name=name,Values=${vmimage}" --owner amazon --query "sort_by(Images, &CreationDate)[-1].ImageId" --output text)
   echo "ami-id: ${ami_id}"
}

get_vm_id() {
   vm_id=$(aws ec2 describe-instances --filter Name=instance.group-name,Values=${name}-sg --query='Reservations[*].Instances[*].InstanceId' --output text)
   echo "vm-id: ${vm_id}"
}

get_ip() {
   ip=$(aws ec2 describe-instances --filter Name=instance.group-name,Values=${name}-sg --query='Reservations[*].Instances[*].PublicIpAddress' --output text)
   echo "vm-ip  : ${ip}"
   ipv6=$(aws ec2 describe-instances --filter Name=instance.group-name,Values=${name}-sg --query='Reservations[*].Instances[*].Ipv6Address' --output text)
   echo "vm-ipv6: ${ipv6}"
}

wait_vm_ready() {
   status=$(aws ec2 describe-instances --filter Name=instance.group-name,Values=${name}-sg --query='Reservations[*].Instances[*].State.Name' --output text)
   while [ "${status}" != "running" ] ; do
      echo "vm: ${status}, waiting for running"
      sleep 10
      status=$(aws ec2 describe-instances --filter Name=instance.group-name,Values=${name}-sg --query='Reservations[*].Instances[*].State.Name' --output text)
   done
   echo "vm: ${status}"
}

wait_vm_terminated() {
   status=$(aws ec2 describe-instances --filter Name=instance.group-name,Values=${name}-sg --query='Reservations[*].Instances[*].State.Name' --output text)
   while [ "${status}" = "running" ] || [ "${status}" = "shutting-down" ] ; do
      echo "vm: ${status}, waiting"
      sleep 10
      status=$(aws ec2 describe-instances --filter Name=instance.group-name,Values=${name}-sg --query='Reservations[*].Instances[*].State.Name' --output text)
   done
   echo "vm: ${status}"
}

provider_create_cloud_vm() {
   echo "create aws server ${name}"

   get_ami

   aws ec2 create-security-group --group-name ${name}-sg --description "${name} security group" --output text

   aws ec2 authorize-security-group-ingress --group-name ${name}-sg --ip-permissions \
      IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges='[{CidrIp=0.0.0.0/0}]' \
      IpProtocol=tcp,FromPort=22,ToPort=22,Ipv6Ranges='[{CidrIpv6=::/0}]' \
      IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges='[{CidrIp=0.0.0.0/0}]' \
      IpProtocol=tcp,FromPort=80,ToPort=80,Ipv6Ranges='[{CidrIpv6=::/0}]' \
      IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges='[{CidrIp=0.0.0.0/0}]' \
      IpProtocol=tcp,FromPort=443,ToPort=443,Ipv6Ranges='[{CidrIpv6=::/0}]' \
      IpProtocol=udp,FromPort=5684,ToPort=5684,IpRanges='[{CidrIp=0.0.0.0/0}]' \
      IpProtocol=udp,FromPort=5684,ToPort=5684,Ipv6Ranges='[{CidrIpv6=::/0}]' \
      --no-cli-pager

   aws ec2 run-instances --image-id ${ami_id} --count 1 --instance-type ${vmsize} \
      --key-name ${ssh_key_id} --security-groups ${name}-sg --no-cli-pager \
      --user-data file://${cloud_config}

   echo "wait to give vm time to finish the installation!"

   wait_vm_ready

   get_ip

   wait_cloud_init_ready

   echo "use: ssh root@${ip} to login!"
}

provider_delete_cloud_vm() {
   echo "delete aws server ${name}"

   get_vm_id

   if [ -n "${vm_id}" ] ; then
      aws ec2 terminate-instances --instance-ids ${vm_id}
      wait_vm_terminated
      sleep 5
   fi

   aws ec2 delete-security-group --group-name ${name}-sg

}
