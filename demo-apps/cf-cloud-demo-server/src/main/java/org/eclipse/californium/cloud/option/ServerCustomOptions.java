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
package org.eclipse.californium.cloud.option;

import org.eclipse.californium.core.coap.option.OpaqueOption;
import org.eclipse.californium.core.coap.option.OptionDefinition;

/**
 * CoAP custom option for response code of combined forwarded request.
 * 
 * @since 3.13
 */
public class ServerCustomOptions {

	/**
	 * Number of custom option.
	 */
	public static final int COAP_OPTION_READ_ETAG = 0xfdec;

	public static final OpaqueOption.Definition READ_ETAG = new OpaqueOption.Definition(COAP_OPTION_READ_ETAG,
			"Read_Etag", false, 1, 8);

	/**
	 * Number of custom option.
	 */
	public static final int COAP_OPTION_READ_RESPONSE = 0xfdf0;

	public static final ResponseCodeOption.Definition READ_RESPONSE = new ResponseCodeOption.Definition(
			COAP_OPTION_READ_RESPONSE, "Read_ResponseCode");

	public static final TimeOption.Definition TIME = TimeOption.DEFINITION;

	public static final OptionDefinition[] CUSTOM = { READ_ETAG, READ_RESPONSE, TIME };
}
