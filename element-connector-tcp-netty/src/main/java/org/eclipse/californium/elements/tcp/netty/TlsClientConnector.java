/*******************************************************************************
 * Copyright (c) 2016, 2017 Amazon Web Services and others.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.html.
 * <p>
 * Contributors:
 * Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 * Achim Kraus (Bosch Software Innovations GmbH) - create "remote aware" SSLEngine
 * Achim Kraus (Bosch Software Innovations GmbH) - introduce protocol,
 *                                                 remove scheme
 * Achim Kraus (Bosch Software Innovations GmbH) - delay sending message after complete
 *                                                 TLS handshake.
 * Bosch Software Innovations GmbH - migrate to SLF4J
 * Achim Kraus (Bosch Software Innovations GmbH) - add handshake timeout
 * Achim Kraus (Bosch Software Innovations GmbH) - change exception type to
 *                                                 IllegalStateException
 ******************************************************************************/
package org.eclipse.californium.elements.tcp.netty;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;

import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.TlsEndpointContext;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.config.CertificateAuthenticationMode;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.TcpConfig;
import org.eclipse.californium.elements.util.CertPathUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.netty.channel.Channel;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;

/**
 * A TLS client connector that establishes outbound TLS connections.
 */
public class TlsClientConnector extends TcpClientConnector {

	/**
	 * @since 3.10
	 */
	private static final Logger LOG = LoggerFactory.getLogger(TlsClientConnector.class);

	/**
	 * Context to be used to for connections.
	 */
	private final SSLContext sslContext;
	/**
	 * Weak cipher suites, or {@code null}, if no required.
	 * 
	 * @see TlsContextUtil#getWeakCipherSuites(SSLContext)
	 * @since 3.0
	 */
	private final String[] weakCipherSuites;
	/**
	 * Handshake timeout in milliseconds.
	 */
	private final int handshakeTimeoutMillis;
	/**
	 * Verify the server's subject.
	 * 
	 * @since 3.0
	 */
	private final boolean verifyServerSubject;

	/**
	 * Creates TLS client connector with custom SSL context. Useful for using
	 * client keys, or custom trust stores. The context must be initialized by
	 * the caller.
	 * 
	 * @param sslContext ssl context
	 * @param configuration configuration with {@link TcpConfig} definitions.
	 * @since 3.0
	 */
	public TlsClientConnector(SSLContext sslContext, Configuration configuration) {
		super(configuration, new TlsContextUtil(CertificateAuthenticationMode.NEEDED));
		this.sslContext = sslContext;
		this.handshakeTimeoutMillis = configuration.getTimeAsInt(TcpConfig.TLS_HANDSHAKE_TIMEOUT,
				TimeUnit.MILLISECONDS);
		this.verifyServerSubject = configuration.get(TcpConfig.TLS_VERIFY_SERVER_CERTIFICATES_SUBJECT);
		this.weakCipherSuites = TlsContextUtil.getWeakCipherSuites(sslContext);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Delay message sending after TLS handshake is completed.
	 */
	@Override
	protected void send(final Channel channel, final EndpointContextMatcher endpointMatcher, final RawData msg) {
		final SslHandler sslHandler = channel.pipeline().get(SslHandler.class);
		if (sslHandler == null) {
			msg.onError(new IllegalStateException("Missing SslHandler"));
		} else {
			/*
			 * Trigger handshake.
			 */
			Future<Channel> handshakeFuture = sslHandler.handshakeFuture();
			handshakeFuture.addListener(new GenericFutureListener<Future<Channel>>() {

				@Override
				public void operationComplete(Future<Channel> future) throws Exception {
					if (future.isSuccess()) {
						EndpointContext context = contextUtil.buildEndpointContext(channel);
						if (context == null || context.get(TlsEndpointContext.KEY_SESSION_ID) == null) {
							msg.onError(new IllegalStateException("Missing TlsEndpointContext " + context));
							return;
						}
						if (verifyServerSubject) {
							try {
								Principal principal = context.getPeerIdentity();
								if (principal instanceof X509CertPath) {
									X509Certificate target = ((X509CertPath) principal).getTarget();
									InetSocketAddress address = context.getPeerAddress();
									String hostname = context.getVirtualHost();
									verifyCertificatesSubject(hostname, address, target);
								}
							} catch (SSLPeerUnverifiedException ex) {
								msg.onError(ex);
								return;
							}
						}
						/*
						 * Handshake succeeded! Call super.send() to actually
						 * send the message.
						 */
						TlsClientConnector.super.send(future.getNow(), endpointMatcher, msg);
					} else if (future.isCancelled()) {
						msg.onError(new CancellationException());
					} else {
						msg.onError(future.cause());
					}
				}
			});
		}
	}

	@Override
	protected void onNewChannelCreated(SocketAddress remote, Channel ch) {
		SSLEngine sslEngine = createSllEngine(remote);
		sslEngine.setUseClientMode(true);
		if (weakCipherSuites != null) {
			sslEngine.setEnabledCipherSuites(weakCipherSuites);
		}
		SslHandler sslHandler = new SslHandler(sslEngine);
		sslHandler.setHandshakeTimeoutMillis(handshakeTimeoutMillis);
		ch.pipeline().addFirst(sslHandler);
	}

	@Override
	public String getProtocol() {
		return "TLS";
	}

	/**
	 * Create SSL engine for remote socket address.
	 * 
	 * @param remoteAddress for SSL engine
	 * @return created SSL engine
	 */
	private SSLEngine createSllEngine(SocketAddress remoteAddress) {
		if (remoteAddress instanceof InetSocketAddress) {
			LOG.info("Connection to inet {}", StringUtil.toLog(remoteAddress));
			InetSocketAddress remote = (InetSocketAddress) remoteAddress;
			return sslContext.createSSLEngine(remote.getAddress().getHostAddress(), remote.getPort());
		} else {
			LOG.info("Connection to {}", StringUtil.toLog(remoteAddress));
			return sslContext.createSSLEngine();
		}
	}

	/**
	 * Verify the certificate's subject.
	 * 
	 * Considers both destination variants, server names and inet address and
	 * verifies that using the certificate's subject CN and subject alternative
	 * names.
	 * 
	 * @param serverName server name
	 * @param peer remote peer
	 * @param certificate server's certificate
	 * @throws NullPointerException if the certificate or both identities, the
	 *             servername and peer, is {@code null}.
	 * @throws SSLPeerUnverifiedException if the verification fails.
	 * @since 3.0
	 */
	private void verifyCertificatesSubject(String serverName, InetSocketAddress peer, X509Certificate certificate)
			throws SSLPeerUnverifiedException {
		if (certificate == null) {
			throw new NullPointerException("Certficate must not be null!");
		}
		if (serverName == null && peer == null) {
			// nothing to verify
			return;
		}
		String literalIp = null;
		String hostname = serverName;
		if (peer != null) {
			InetAddress destination = peer.getAddress();
			if (destination != null) {
				literalIp = destination.getHostAddress();
			}
			if (hostname == null) {
				hostname = StringUtil.toHostString(peer);
			}
		}
		if (hostname != null && hostname.equals(literalIp)) {
			hostname = null;
		}
		if (hostname != null) {
			if (!CertPathUtil.matchDestination(certificate, hostname)) {
				String cn = CertPathUtil.getSubjectsCn(certificate);
				LOG.debug("Certificate {} validation failed: destination doesn't match", cn);
				throw new SSLPeerUnverifiedException(
						"Certificate " + cn + ": Destination '" + hostname + "' doesn't match!");
			}
		} else {
			if (!CertPathUtil.matchLiteralIP(certificate, literalIp)) {
				String cn = CertPathUtil.getSubjectsCn(certificate);
				LOG.debug("Certificate {} validation failed: literal IP doesn't match", cn);
				throw new SSLPeerUnverifiedException(
						"Certificate " + cn + ": Literal IP " + literalIp + " doesn't match!");
			}
		}
	}

}
