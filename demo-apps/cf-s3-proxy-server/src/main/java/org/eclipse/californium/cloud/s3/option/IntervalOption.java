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

import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.option.IntegerOptionDefinition;

/**
 * CoAP custom interval option.
 * 
 * Used in {@link Request} to indicate the client's interval in milliseconds
 * sending alive requests.
 * 
 * @since 3.12
 */
public class IntervalOption extends Option {

	/**
	 * Number of custom option.
	 */
	public static final int COAP_OPTION_INTERVAL = 0xfdf4;

	public static final IntegerOptionDefinition DEFINITION = new IntegerOptionDefinition(COAP_OPTION_INTERVAL,
			"Interval", true) {

		@Override
		public Option create(byte[] value) {
			return new IntervalOption(value);
		}

	};

	/**
	 * Create time option.
	 * 
	 * @param time time in system milliseconds.
	 */
	public IntervalOption(long time) {
		super(DEFINITION, time);
	}

	/**
	 * Create time option.
	 * 
	 * @param value time in system milliseconds as byte array.
	 */
	public IntervalOption(byte[] value) {
		super(DEFINITION, value);
	}
}
