package org.eclipse.californium.elements.tcp;

import io.netty.channel.Channel;
import io.netty.handler.ssl.SslHandler;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

/**
 * A TCP client connector that establishes outbound TLS connections.
 */
public class TlsClientConnector extends TcpClientConnector {

	private final SSLContext sslContext;

	/**
	 * Creates TLS client connector with custom SSL context. Useful for using client keys, or custom trust stores. The
	 * context must be initialized by the caller.
	 */
	public TlsClientConnector(SSLContext sslContext, int numberOfThreads, int connectTimeoutMillis, int idleTimeout) {
		super(numberOfThreads, connectTimeoutMillis, idleTimeout);
		this.sslContext = sslContext;
	}

	/**
	 * Creates new TLS client connector that uses default JVM SSL configuration.
	 */
	public TlsClientConnector(int numberOfThreads, int connectTimeoutMillis, int idleTimeout) {
		super(numberOfThreads, connectTimeoutMillis, idleTimeout);

		try {
			this.sslContext = SSLContext.getInstance("TLS");
			this.sslContext.init(null, null, null);
		} catch (NoSuchAlgorithmException | KeyManagementException e) {
			throw new RuntimeException("Unable to initialize SSL context", e);
		}
	}

	@Override protected void onNewChannelCreated(Channel ch) {
		SSLEngine sslEngine = sslContext.createSSLEngine();
		sslEngine.setUseClientMode(true);
		ch.pipeline().addFirst(new SslHandler(sslEngine));
	}

	@Override public boolean isSchemeSupported(String scheme) {
		return "coaps+tcp".equals(scheme);
	}
}
