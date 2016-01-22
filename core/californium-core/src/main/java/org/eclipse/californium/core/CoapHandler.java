/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 ******************************************************************************/
package org.eclipse.californium.core;

import org.eclipse.californium.core.CoapResponse;

/**
 * A CoapHandler can be used to asynchronously react to responses from a CoAP
 * client. When a response or in case of a CoAP observe relation a notification
 * arrives, the method {@link #onLoad(CoapResponse)} is invoked. If a request
 * timeouts or the server rejects it, the method {@link #onError()} is invoked.
 */
public interface CoapHandler {

	/**
	 * Invoked when a CoAP response or notification has arrived.
	 *
	 * @param response the response
	 */
	public void onLoad(CoapResponse response);
	
	/**
	 * Invoked when a request timeouts or has been rejected by the server.
	 */
	public void onError();

}
