/*******************************************************************************
 * Copyright (c) 2016, 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation.
 *                                      Derived from NettyContextUtils.
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove spaces from session id.
 ******************************************************************************/
package org.eclipse.californium.elements.tcp.netty;

import java.net.InetSocketAddress;
import java.security.Principal;
import java.security.cert.Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.TlsEndpointContext;
import org.eclipse.californium.elements.util.StringUtil;

import io.netty.channel.Channel;
import io.netty.handler.ssl.SslHandler;

/**
 * Util for building for TLS endpoint context from channel.
 */
public class TlsContextUtil extends TcpContextUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(TlsContextUtil.class);

	/**
	 * Log warn messages, if remote peer's principal is not valid.
	 */
	private final boolean warnMissingPrincipal;

	/**
	 * Create utility instance.
	 * 
	 * @param warnMissingPrincipal {@code true}, to log warn messages, if remote
	 *            peer's principal is not valid. {@code false}, to log trace
	 *            messages.
	 */
	public TlsContextUtil(boolean warnMissingPrincipal) {
		this.warnMissingPrincipal = warnMissingPrincipal;
	}

	/**
	 * Build endpoint context related to the provided channel.
	 * 
	 * @param channel channel of endpoint context
	 * @return endpoint context
	 * @throws IllegalStateException if no {@link SslHandler} is available or
	 *             the handshake isn't finished yet.
	 */
	@Override
	public EndpointContext buildEndpointContext(Channel channel) {
		InetSocketAddress address = (InetSocketAddress) channel.remoteAddress();
		String id = channel.id().asShortText();
		SslHandler sslHandler = channel.pipeline().get(SslHandler.class);
		if (sslHandler == null) {
			throw new IllegalStateException("Missing SslHandler for " + id + "!");
		}
		SSLEngine sslEngine = sslHandler.engine();
		SSLSession sslSession = sslEngine.getSession();
		if (sslSession != null) {
			boolean checkKerberos = false;
			Principal principal = null;
			try {
				Certificate[] peerCertificateChain = sslSession.getPeerCertificates();
				if (peerCertificateChain != null && peerCertificateChain.length != 0) {
					principal = X509CertPath.fromCertificatesChain(peerCertificateChain);
				} else {
					// maybe kerberos is used and therefore
					// getPeerCertificates fails
					checkKerberos = true;
				}
			} catch (SSLPeerUnverifiedException e1) {
				// maybe kerberos is used and therefore
				// getPeerCertificates fails
				checkKerberos = true;
			} catch (RuntimeException e) {
				LOGGER.warn("TLS({}) failed to extract principal {}", id, e.getMessage());
			}

			if (checkKerberos) {
				try {
					principal = sslSession.getPeerPrincipal();
				} catch (SSLPeerUnverifiedException e2) {
					// still unverified, so also no kerberos
					if (warnMissingPrincipal) {
						LOGGER.warn("TLS({}) failed to verify principal, {}", id, e2.getMessage());
					} else {
						LOGGER.trace("TLS({}) failed to verify principal, {}", id, e2.getMessage());
					}
				}
			}

			if (principal != null) {
				LOGGER.debug("TLS({}) Principal {}", id, principal.getName());
			} else if (warnMissingPrincipal) {
				LOGGER.warn("TLS({}) principal missing", id);
			} else {
				LOGGER.trace("TLS({}) principal missing", id);
			}

			byte[] sessionId = sslSession.getId();
			if (sessionId != null && sessionId.length > 0) {
				String sslId = StringUtil.byteArray2HexString(sessionId, StringUtil.NO_SEPARATOR, 0);
				String cipherSuite = sslSession.getCipherSuite();
				LOGGER.debug("TLS({},{},{})", id, StringUtil.trunc(sslId, 14), cipherSuite);
				return new TlsEndpointContext(address, principal, id, sslId, cipherSuite, sslSession.getLastAccessedTime());
			}
		}
		// TLS handshake not finished
		throw new IllegalStateException("TLS handshake " + id + " not ready!");
	}
}
