/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.core.server;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;

/**
 * Exception reporting an error delivering a request, different from
 * {@link ResponseCode#NOT_FOUND}.
 * 
 * @since 3.0
 */
public class DelivererException extends Exception {

	private static final long serialVersionUID = 123L;

	/**
	 * Error response code of delivering.
	 */
	private final ResponseCode response;

	/**
	 * Create a deliverer error response.
	 * 
	 * @param response error response code
	 * @param message diagnostic message
	 * @throws IllegalArgumentException if response code is no error.
	 */
	public DelivererException(ResponseCode response, String message) {
		super(message);
		if (response.isClientError() || response.isServerError()) {
			this.response = response;
		} else {
			throw new IllegalArgumentException("response code " + response + " must be an error-code!");
		}
	}

	/**
	 * Get error response code.
	 * 
	 * @return error response code
	 */
	public ResponseCode getErrorResponseCode() {
		return response;
	}
}
