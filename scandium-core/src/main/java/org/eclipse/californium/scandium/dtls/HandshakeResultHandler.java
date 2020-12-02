/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

/**
 * Handler for asynchronous handshake results.
 * 
 * The implementation must take care, that the calling thread is undefined.
 * 
 * @since 2.5
 */
public interface HandshakeResultHandler {

	/**
	 * Apply handshake result.
	 * 
	 * @param handshakeResult handshake result
	 */
	void apply(HandshakeResult handshakeResult);

}
