/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.cloud.s3.option;

import org.eclipse.californium.cloud.option.ResponseCodeOption;
import org.eclipse.californium.core.coap.option.IntegerOption;
import org.eclipse.californium.core.coap.option.OptionDefinition;

/**
 * CoAP custom option for response code of combined forwarded request.
 * 
 * @since 3.13
 */
public class S3ProxyCustomOptions {

	/**
	 * Number of custom option forward response code.
	 */
	public static final int COAP_OPTION_FORWARD_RESPONSE = 0xfdf8;

	public static final ResponseCodeOption.Definition FORWARD_RESPONSE = new ResponseCodeOption.Definition(
			COAP_OPTION_FORWARD_RESPONSE, "Forward_ResponseCode");

	/**
	 * Number of custom option interval.
	 */
	public static final int COAP_OPTION_INTERVAL = 0xfdf4;

	public static final IntegerOption.Definition INTERVAL = new IntegerOption.Definition(COAP_OPTION_INTERVAL,
			"Interval", true);

	public static final OptionDefinition[] CUSTOM = { FORWARD_RESPONSE, INTERVAL };

}
