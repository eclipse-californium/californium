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
package org.eclipse.californium.proxy2.http;

import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.message.StatusLine;
import org.apache.hc.core5.http.nio.AsyncEntityProducer;
import org.apache.hc.core5.http.nio.support.BasicResponseProducer;

/**
 * Response producer for proxy.
 * 
 * @since 3.0
 */
public class ProxyResponseProducer extends BasicResponseProducer {

	/**
	 * Http response.
	 */
	private HttpResponse httpResponse;

	/**
	 * Create instance of response producer.
	 * 
	 * @param httpResponse http response
	 * @param httpEntity http entity
	 */
	public ProxyResponseProducer(HttpResponse httpResponse, AsyncEntityProducer httpEntity) {
		super(httpResponse, httpEntity);
		this.httpResponse = httpResponse;
	}

	/**
	 * Get http response.
	 * 
	 * @return http response
	 */
	public HttpResponse getHttpResponse() {
		return httpResponse;
	}

	/**
	 * Get http status line.
	 * 
	 * @return http status line
	 */
	public StatusLine getStatusLine() {
		return new StatusLine(httpResponse);
	}
}
