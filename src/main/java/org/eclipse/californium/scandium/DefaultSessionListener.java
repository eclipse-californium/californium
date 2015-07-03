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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - intial creation
 *******************************************************************************/
package org.eclipse.californium.scandium;

import java.net.InetSocketAddress;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.Handshaker;
import org.eclipse.californium.scandium.dtls.SessionListener;
import org.eclipse.californium.scandium.dtls.SessionStore;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.util.LeastRecentlyUsedCache;

public class DefaultSessionListener implements SessionListener {
	
	private static final Logger LOGGER = Logger.getLogger(DefaultSessionListener.class.getName());
	private final SessionStore sessionStore;
	private final LeastRecentlyUsedCache<InetSocketAddress, Handshaker> handshakers;
	
	public DefaultSessionListener(SessionStore sessionStore,
			LeastRecentlyUsedCache<InetSocketAddress, Handshaker> handshakers) {
		this.sessionStore = sessionStore;
		this.handshakers = handshakers;
	}

	@Override
	public void handshakeStarted(Handshaker handshaker) throws HandshakeException {
		if (handshaker != null) {
			if (!handshakers.put(handshaker.getPeerAddress(), handshaker)) {
				throw new HandshakeException(
						"Maximum number of simultanous handshakes in progress",
						new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, handshaker.getPeerAddress()));
			} else {
				LOGGER.log(Level.FINE, "Handshake with [{0}] has been started", handshaker.getPeerAddress());
			}
		}
	}
	
	@Override
	public void sessionEstablished(Handshaker handshaker, DTLSSession session)
		throws HandshakeException {
		if (handshaker != null && session != null && session.isActive()) {
			if (!sessionStore.put(session)) {
				handshakers.remove(handshaker.getPeerAddress());
				throw new HandshakeException(
						"Maximum number of sessions has been established",
						new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, session.getPeer()));
			} else {
				LOGGER.log(Level.FINE, "Session with [{0}] has been established", session.getPeer());
			}
		}
	}
	
	@Override
	public void handshakeCompleted(InetSocketAddress peer) {
		if (peer != null) {
			Handshaker completedHandshaker = handshakers.remove(peer);
			if (completedHandshaker != null) {
				LOGGER.log(Level.FINE, "Handshake with [{0}] has been completed", peer);
			}
		}
	}
}
