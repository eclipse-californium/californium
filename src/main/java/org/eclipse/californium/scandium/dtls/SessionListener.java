/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Initial creation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 464383
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

/**
 * A listener for life-cycle events of <code>DTLSSession</code>s.
 * 
 */
public interface SessionListener {

	/**
	 * Indicates that the handshake for a session has successfully
	 * completed.
	 * 
	 * In particular this means that the session negotiated by the
	 * handshaker (accessible via its {@link Handshaker#getSession()}
	 * method) can now be used to exchange application layer data.
	 * 
	 * @param handshaker the finished handshaker
	 * @param negotiatedSession the session that has been established by
	 *          the handshaker
	 * @throws NullPointerException if any of the parameters is <code>null</code>
	 */
	void handshakeCompleted(Handshaker handshaker, DTLSSession negotiatedSession);
}
