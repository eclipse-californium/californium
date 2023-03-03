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
#      copy a different used name to "ssh_key_id" below.s
#
# Adapt the the "vmsize" according your requirements and wanted price.
# See https://aws.amazon.com/ec2/pricing/


provider_enable_s3_acl() {
   echo "Enable ACL for aws s3 bucket ${s3bucket}"
      
   aws s3api put-public-access-block --bucket ${s3bucket} --public-access-block-configuration \
    "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"

   aws s3api put-bucket-ownership-controls --bucket ${s3bucket} \
     --ownership-controls="Rules=[{ObjectOwnership=BucketOwnerPreferred}]"
      
}


