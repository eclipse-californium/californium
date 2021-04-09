/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Francesco Corazza - HTTP cross-proxy
 ******************************************************************************/
package org.eclipse.californium.proxy2;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;

/**
 * The Class InvalidMethodException.
 */
public class InvalidMethodException extends TranslationException {

	private static final long serialVersionUID = 1L;

	private final ResponseCode error;

	public InvalidMethodException() {
		this(ResponseCode.BAD_GATEWAY);
	}

	public InvalidMethodException(ResponseCode error) {
		super(error.name());
		this.error = error;
	}

	public ResponseCode getError() {
		return error;
	}
}
