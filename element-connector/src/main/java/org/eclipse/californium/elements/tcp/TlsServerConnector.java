package org.eclipse.californium.elements.tcp;

import io.netty.channel.Channel;
import io.netty.handler.ssl.SslHandler;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.net.InetSocketAddress;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

/**
 * A TCP client connector that establishes outbound TLS connections.
 */
public class TlsServerConnector extends TcpServerConnector {

	private final SSLContext sslContext;

	/**
	 * Initializes SSLEngine with specified SSL engine.
	 */
	public TlsServerConnector(SSLContext sslContext, InetSocketAddress socketAddress, int numberOfThreads,
			int idleTimeout) {
		super(socketAddress, numberOfThreads, idleTimeout);
		this.sslContext = sslContext;
	}

	/**
	 * Initializes SSLEngine with specified SSL key management factory.
	 */
	public TlsServerConnector(KeyManagerFactory keyManagerFactory, InetSocketAddress socketAddress, int numberOfThreads,
			int idleTimeout) {
		super(socketAddress, numberOfThreads, idleTimeout);

		try {
			this.sslContext = SSLContext.getInstance("TLS");
			this.sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
		} catch (KeyManagementException | NoSuchAlgorithmException e) {
			throw new RuntimeException("Unable to initialize SSL engine", e);
		}
	}

	@Override protected void onNewChannelCreated(Channel ch) {
		SSLEngine sslEngine = sslContext.createSSLEngine();
		sslEngine.setUseClientMode(false);
		ch.pipeline().addFirst(new SslHandler(sslEngine));
	}

	@Override public boolean isSchemeSupported(String scheme) {
		return "coaps+tcp".equals(scheme);
	}
}
