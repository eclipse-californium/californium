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

import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;

/**
 * The http-result.
 * 
 * @since 3.0
 */
public class HttpResult {

	/**
	 * Principal, if https is used.
	 */
	private Principal peerPrincipal;
	/**
	 * Http response code.
	 */
	private int responseCode;
	/**
	 * Http response message.
	 */
	private String responseMessage;
	/**
	 * Content input stream.
	 */
	private InputStream content;

	/**
	 * Create http result.
	 * 
	 * @param responseCode response code.
	 * @param responseMessage response message
	 * @param peerPrincipal peer's principal. May be {@code null}.
	 * @param content response content. May be {@code null}.
	 */
	public HttpResult(int responseCode, String responseMessage, Principal peerPrincipal, InputStream content) {
		this.responseCode = responseCode;
		this.responseMessage = responseMessage;
		this.peerPrincipal = peerPrincipal;
		this.content = content;
	}

	/**
	 * Get principal.
	 * 
	 * @return principal, or {@code null}, if not available.
	 */
	public Principal getPeerPrincipal() {
		return peerPrincipal;
	}

	/**
	 * Get response code.
	 * 
	 * @return response code, {@code 0}, if not available.
	 */
	public int getResponseCode() {
		return responseCode;
	}

	/**
	 * Get response message.
	 * 
	 * @return response message, {@code null}, if not available.
	 */
	public String getResponseMessage() {
		return responseMessage;
	}

	/**
	 * Get content input stream.
	 * 
	 * @return content input stream, {@code null}, if not available.
	 */
	public InputStream getContent() {
		return content;
	}

	/**
	 * Close content input stream.
	 */
	public void close() {
		if (content != null) {
			try {
				content.close();
			} catch (IOException e) {
			}
		}
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append(responseCode).append(", ").append(responseMessage);
		return builder.toString();
	}

}
