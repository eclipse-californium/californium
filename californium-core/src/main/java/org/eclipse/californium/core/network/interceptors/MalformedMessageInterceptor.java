/*******************************************************************************
 * Copyright (c) 2022 Contributors to the Eclipse Foundation.
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

import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.elements.RawData;

/**
 * Counter for malformed messages.
 * 
 * Only supported for
 * {@link CoapEndpoint#addPostProcessInterceptor(MessageInterceptor)}.
 * 
 * @since 3.7
 */
public interface MalformedMessageInterceptor extends MessageInterceptor {

	/**
	 * Received malformed message.
	 * 
	 * @param message received malformed message.
	 */
	void receivedMalformedMessage(RawData message);

}
