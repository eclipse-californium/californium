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
package org.eclipse.californium.cli;

import java.net.InetSocketAddress;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.StringUtil;

import picocli.CommandLine;
import picocli.CommandLine.ITypeConverter;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

/**
 * Client basic command line config
 * 
 * @since 2.3
 */
public class ClientBaseConfig extends ConnectorConfig {

	/**
	 * Proxy configuration.
	 */
	@Option(names = "--proxy", description = "use proxy. <address>:<port>[:<scheme>]. Default env-value of COAP_PROXY.")
	public ProxyConfiguration proxy;

	/**
	 * Destination URI.
	 */
	@Parameters(index = "0", paramLabel = "URI", arity = "0..1", defaultValue = "californium.eclipse.org", description = "destination URI. Default .")
	public String uri;

	/**
	 * {@code true}, if DTLS or TLS is selected, {@code false}, otherwise.
	 */
	public boolean secure;
	/**
	 * {@code true}, if TCP or TLS is selected, {@code false}, otherwise.
	 */
	public boolean tcp;

	@Override
	public void register(CommandLine cmd) {
		super.register(cmd);
		cmd.registerConverter(ProxyConfiguration.class, proxyReader);
	}

	@Override
	public void defaults() {
		super.defaults();
		if (proxy == null) {
			String proxySpec = StringUtil.getConfiguration("COAP_PROXY");
			if (proxySpec != null && !proxySpec.isEmpty()) {
				try {
					proxy = proxyReader.convert(proxySpec);
				} catch (Exception e) {
				}
			}
		}
		// allow quick hostname as argument
		if (uri.indexOf("://") == -1) {
			if (authenticationModes != null && !authenticationModes.isEmpty()) {
				uri = CoAP.COAP_SECURE_URI_SCHEME + "://" + uri;
				secure = true;
			} else {
				uri = CoAP.COAP_URI_SCHEME + "://" + uri;
			}
		} else {
			secure = uri.startsWith(CoAP.COAP_SECURE_URI_SCHEME + "://")
					|| uri.startsWith(CoAP.COAP_SECURE_TCP_URI_SCHEME + "://");
			tcp = uri.startsWith(CoAP.COAP_TCP_URI_SCHEME + "://")
					|| uri.startsWith(CoAP.COAP_SECURE_TCP_URI_SCHEME + "://");
		}
		if (uri.endsWith("/")) {
			uri = uri.substring(uri.length() - 1);
		}
	}

	/**
	 * Create client config clone with different PSK identity and secret.
	 * 
	 * @param id psk identity
	 * @param secret secret. if {@code null} and
	 *            {@link ClientInitializer#PSK_IDENTITY_PREFIX} is used, use
	 *            {@link ClientInitializer#PSK_SECRET}
	 * @return create client config clone.
	 */
	public ClientBaseConfig create(String id, byte[] secret) {
		ClientBaseConfig clone = null;
		try {
			clone = (ClientBaseConfig) clone();
			clone.identity = id;
			clone.secretKey = secret;
		} catch (CloneNotSupportedException e) {
			e.printStackTrace();
		}
		return clone;
	}

	/**
	 * Create client config clone with different ec key pair.
	 * 
	 * @param privateKey private key
	 * @param publicKey public key
	 * @return create client config clone.
	 */
	public ClientBaseConfig create(PrivateKey privateKey, PublicKey publicKey) {
		ClientBaseConfig clone = null;
		try {
			clone = (ClientBaseConfig) clone();
			clone.credentials = new SslContextUtil.Credentials(privateKey, publicKey, null);
		} catch (CloneNotSupportedException e) {
			e.printStackTrace();
		}
		return clone;
	}

	/**
	 * Reader for proxy configuration.
	 */
	private static ITypeConverter<ProxyConfiguration> proxyReader = new ITypeConverter<ProxyConfiguration>() {

		@Override
		public ProxyConfiguration convert(String value) throws Exception {
			int index;
			String config = value;
			String host;
			if (config.startsWith("[")) {
				index = config.indexOf("]:");
				if (index < 0) {
					throw new IllegalArgumentException(value + " invalid proxy configuration!");
				}
				host = config.substring(0, index + 1);
				config = config.substring(index + 2);
			} else {
				index = config.indexOf(":");
				if (index < 0) {
					throw new IllegalArgumentException(value + " invalid proxy configuration!");
				}
				host = config.substring(0, index);
				config = config.substring(index + 1);
			}
			String scheme = null;
			index = config.indexOf(":");
			if (index > 0) {
				scheme = config.substring(index + 1);
				config = config.substring(0, index);
			}
			try {
				InetSocketAddress destination = new InetSocketAddress(host, Integer.parseInt(config));
				return new ProxyConfiguration(scheme, destination);
			} catch (Throwable ex) {
				throw new IllegalArgumentException(value + " invalid proxy configuration!", ex);
			}
		}

	};

	/**
	 * Proxy configuration.
	 * 
	 * @since 2.3
	 */
	public static class ProxyConfiguration {

		public final String scheme;
		public final InetSocketAddress destination;

		public ProxyConfiguration(String scheme, InetSocketAddress destination) {
			if (destination == null) {
				throw new NullPointerException("proxy destination must not be null!");
			}
			this.scheme = scheme;
			this.destination = destination;
		}

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			builder.append(StringUtil.toString(destination));
			if (scheme != null) {
				builder.append(" using ").append(scheme);
			}
			return builder.toString();
		}

	}

}
