/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.cluster;

import java.io.InputStream;
import java.security.Principal;

/**
 * The http-result exception.
 * 
 * Indicates, that the http result is not as expected.
 * 
 * @since 3.0
 */
public class HttpResultException extends Exception {

	private static final long serialVersionUID = 1L;

	/**
	 * Http result.
	 */
	private HttpResult result;

	/**
	 * Create http result exception.
	 * 
	 * @param result http result
	 */
	public HttpResultException(HttpResult result) {
		super(result.toString());
		this.result = result;
	}

	/**
	 * Get principal.
	 * 
	 * @return principal, or {@code null}, if not available.
	 */
	public Principal getPeerPrincipal() {
		return result.getPeerPrincipal();
	}

	/**
	 * Get response code.
	 * 
	 * @return response code, {@code 0}, if not available.
	 */
	public int getResponseCode() {
		return result.getResponseCode();
	}

	/**
	 * Get response message.
	 * 
	 * @return response message, {@code null}, if not available.
	 */
	public String getResponseMessage() {
		return result.getResponseMessage();
	}

	/**
	 * Get content input stream.
	 * 
	 * @return content input stream, {@code null}, if not available.
	 */
	public InputStream getContent() {
		return result.getContent();
	}

	/**
	 * Close content input stream.
	 */
	public void close() {
		result.close();
	}

}
