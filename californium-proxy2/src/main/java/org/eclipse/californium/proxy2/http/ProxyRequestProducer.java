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

import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.message.RequestLine;
import org.apache.hc.core5.http.nio.AsyncEntityProducer;
import org.apache.hc.core5.http.nio.support.BasicRequestProducer;

/**
 * Request producer for proxy.
 * 
 * @since 3.0
 */
public class ProxyRequestProducer extends BasicRequestProducer {

	/**
	 * Http request.
	 */
	private HttpRequest httpRequest;

	/**
	 * Create instance of request producer.
	 * 
	 * @param httpRequest http request
	 * @param httpEntity http entity
	 */
	public ProxyRequestProducer(HttpRequest httpRequest, AsyncEntityProducer httpEntity) {
		super(httpRequest, httpEntity);
		this.httpRequest = httpRequest;
	}

	/**
	 * Get http request.
	 * 
	 * @return http request
	 */
	public HttpRequest getHttpRequest() {
		return httpRequest;
	}

	/**
	 * Get http request line.
	 * 
	 * @return http request line
	 */
	public RequestLine getRequestLine() {
		return new RequestLine(httpRequest);
	}
}
