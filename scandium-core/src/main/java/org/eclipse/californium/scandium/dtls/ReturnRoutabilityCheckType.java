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
package org.eclipse.californium.scandium.dtls;

/**
 * Return routability check message type.
 * <p>
 * See <a href= "https://tlswg.org/dtls-rrc/draft-ietf-tls-dtls-rrc.html" target
 * ="_blank">dtls-rrc/draft-ietf-tls-dtls-rrc, Return Routability Check for DTLS
 * 1.2 and DTLS 1.3</a>.
 * 
 * @since 3.12
 */
public enum ReturnRoutabilityCheckType {

	PATH_CHALLENGE(0, "Path Challenge (0)"), PATH_RESPONSE(1, "Path Response (1)"), PATH_DROP(2, "Path Drop (2)");

	private final int code;
	private final String text;

	public int getCode() {
		return code;
	}

	ReturnRoutabilityCheckType(int code, String text) {
		this.code = code;
		this.text = text;
	}

	/**
	 * Returns the return routability check message type according to the given
	 * code.
	 * 
	 * @param code the code representation of the return routability check
	 *            message type (i.e. 0, 1, 2).
	 * @return the return routability check message type.
	 */
	public static ReturnRoutabilityCheckType getTypeByValue(int code) {
		switch (code) {
		case 0:
			return ReturnRoutabilityCheckType.PATH_CHALLENGE;
		case 1:
			return ReturnRoutabilityCheckType.PATH_RESPONSE;
		case 2:
			return ReturnRoutabilityCheckType.PATH_DROP;
		default:
			return null;
		}
	}

	@Override
	public String toString() {
		return text;
	}
}
