/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation. 
 *                                      add support for correlation context
 *    Achim Kraus (Bosch Software Innovations GmbH) - add principal and 
 *                                                    add TLS information to
 *                                                    correlation context
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.TcpEndpointContext;
import org.eclipse.californium.elements.TlsEndpointContext;
import org.eclipse.californium.elements.util.StringUtil;

import io.netty.channel.Channel;
import io.netty.handler.ssl.SslHandler;

/**
 * Utils for building for TCP/TLS endpoint context from channel.
 */
public class NettyContextUtils {

	private static final Logger LOGGER = Logger.getLogger(NettyContextUtils.class.getName());
	private static final Level LEVEL = Level.FINER;

	/**
	 * Build endpoint context related to the provided channel.
	 * 
	 * @param channel channel of endpoint context
	 * @return endpoint context
	 */
	public static EndpointContext buildEndpointContext(Channel channel) {
		InetSocketAddress address = (InetSocketAddress) channel.remoteAddress();
		String id = channel.id().asShortText();
		SslHandler sslHandler = channel.pipeline().get(SslHandler.class);
		if (sslHandler != null) {
			SSLEngine sslEngine = sslHandler.engine();
			SSLSession sslSession = sslEngine.getSession();
			if (sslSession != null) {
				Principal principal = null;
				try {
					principal = sslSession.getPeerPrincipal();
					if (principal == null) {
						LOGGER.log(Level.WARNING, "Principal missing");
					} else {
						LOGGER.log(LEVEL, "Principal {0}", principal.getName());
					}
				} catch (SSLPeerUnverifiedException e) {
					LOGGER.log(Level.WARNING, "Principal {0}", e.getMessage());
					/* ignore it */
				}

				byte[] sessionId = sslSession.getId();
				if (sessionId != null && sessionId.length > 0) {
					String sslId = StringUtil.byteArray2HexString(sessionId, 0);
					String cipherSuite = sslSession.getCipherSuite();
					LOGGER.log(LEVEL, "TLS({0},{1},{2})",
							new Object[] { id, StringUtil.trunc(sslId, 14), cipherSuite });
					return new TlsEndpointContext(address, principal, id, sslId, cipherSuite);
				}
			}
			// TLS handshake not finished
			throw new IllegalStateException("TLS handshake " + id + " not ready!");
		}

		LOGGER.log(LEVEL, "TCP({0})", id);
		return new TcpEndpointContext(address, id);
	}
}
