/*******************************************************************************
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
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
 ******************************************************************************/
package org.eclipse.californium.core.network.interceptors;

import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;

/**
 * Counter for responses dropped for no-response option.
 * 
 * Only supported for
 * {@link CoapEndpoint#addPostProcessInterceptor(MessageInterceptor)}.
 * 
 * @since 4.0
 */
public interface NoResponseInterceptor extends MessageInterceptor {

	/**
	 * Drops response for no-response request.
	 * 
	 * @param response to drop.
	 */
	default void dropForNoResponse(Response response) {
		// empty by intention
	}

}
