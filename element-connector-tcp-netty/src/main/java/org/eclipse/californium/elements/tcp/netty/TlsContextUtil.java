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

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.config.CertificateAuthenticationMode;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.TlsEndpointContext;
import org.eclipse.californium.elements.util.JceProviderUtil;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.StringUtil;

import io.netty.channel.Channel;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.AttributeKey;

/**
 * Util for building for TLS endpoint context from channel.
 * 
 * Note: since 3.8 the {@link Principal} and the session_id are cached using the
 * {@link SSLSession#getLastAccessedTime()} to refresh them from the SSLSession.
 */
public class TlsContextUtil extends TcpContextUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(TlsContextUtil.class);

	/**
	 * Key for TLS connect timestamp.
	 * 
	 * @since 3.8
	 */
	private static final AttributeKey<Long> tlsConnectTimestamp = AttributeKey.newInstance("tls_connect_millis");
	/**
	 * Key for TLS principal.
	 * 
	 * @since 3.8
	 */
	private static final AttributeKey<Principal> tlsPrincipal = AttributeKey.newInstance("tls_principal");
	/**
	 * Key for TLS session id.
	 * 
	 * @since 3.8
	 */
	private static final AttributeKey<String> tlsSessionId = AttributeKey.newInstance("tls_session_id");

	/**
	 * Client authentication mode.
	 * 
	 * Depending on the authentication mode, log warn or trace messages, if
	 * remote peer's principal is not valid.
	 * 
	 * @since 3.0 (replaces warnMissingPrincipal)
	 */
	private final CertificateAuthenticationMode clientAuthMode;

	/**
	 * Create utility instance.
	 * 
	 * @param clientAuthMode Client authentication mode. If {@code NEEDED}, log
	 *            warn messages, if remote peer's principal is not valid. If
	 *            {@code WANTED}, log trace messages.
	 */
	public TlsContextUtil(CertificateAuthenticationMode clientAuthMode) {
		this.clientAuthMode = clientAuthMode;
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
			long accessTime = sslSession.getLastAccessedTime();
			Principal principal = null;
			String sslId = null;
			Long contextAccessTime = channel.attr(tlsConnectTimestamp).get();
			if (contextAccessTime == null || accessTime != contextAccessTime.longValue()) {
				boolean checkKerberos = false;
				if (clientAuthMode.useCertificateRequest()) {
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
							if (clientAuthMode == CertificateAuthenticationMode.NEEDED) {
								LOGGER.warn("TLS({}) failed to verify principal, {}", id, e2.getMessage());
							} else {
								LOGGER.trace("TLS({}) failed to verify principal, {}", id, e2.getMessage());
							}
						}
					}

					if (principal != null) {
						LOGGER.debug("TLS({}) Principal {}", id, principal.getName());
					} else if (clientAuthMode == CertificateAuthenticationMode.NEEDED) {
						LOGGER.warn("TLS({}) principal missing", id);
					} else {
						LOGGER.trace("TLS({}) principal missing", id);
					}
				}
				byte[] sessionId = sslSession.getId();
				if (sessionId != null && sessionId.length > 0) {
					sslId = StringUtil.byteArray2HexString(sessionId, StringUtil.NO_SEPARATOR, 0);
					// cache session_id and principal
					channel.attr(tlsConnectTimestamp).set(accessTime);
					channel.attr(tlsPrincipal).set(principal);
					channel.attr(tlsSessionId).set(sslId);
				}
			} else {
				// load session_id and principal from cache
				principal = channel.attr(tlsPrincipal).get();
				sslId = channel.attr(tlsSessionId).get();
			}
			if (sslId != null) {
				String cipherSuite = sslSession.getCipherSuite();
				LOGGER.debug("TLS({},{},{})", id, StringUtil.trunc(sslId, 14), cipherSuite);
				return new TlsEndpointContext(address, principal, id, sslId, cipherSuite, accessTime);
			}
		}
		// TLS handshake not finished
		throw new IllegalStateException("TLS handshake " + id + " not ready!");
	}

	/**
	 * Get array of weak cipher suites.
	 * 
	 * Work-around for
	 * <a href="https://github.com/bcgit/bc-java/issues/1054" target=
	 * "_blank">Bouncy Castle issue 1054: Default cipher suites when running
	 * with java 7 (restricted)</a>. Fixed with bouncy castle 1.7.0.
	 * 
	 * @param sslContext ssl context with default cipher suite
	 * @return array with weak cipher suites, subset of the ssl context.
	 *         {@code null}, if not required.
	 * 
	 * @see JceProviderUtil#usesBouncyCastle()
	 * @see JceProviderUtil#getProviderVersion()
	 * @see JceProviderUtil#hasStrongEncryption()
	 * @see SslContextUtil#getWeakCipherSuites(SSLContext)
	 * @since 3.3
	 */
	public static String[] getWeakCipherSuites(SSLContext sslContext) {
		if (!JceProviderUtil.hasStrongEncryption() && JceProviderUtil.usesBouncyCastle()
				&& JceProviderUtil.getProviderVersion().compareTo("1.70") < 0) {
			return SslContextUtil.getWeakCipherSuites(sslContext);
		}
		return null;
	}
}
