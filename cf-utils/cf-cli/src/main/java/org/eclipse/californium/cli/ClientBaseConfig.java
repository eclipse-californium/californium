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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.StringUtil;

import picocli.CommandLine;
import picocli.CommandLine.IDefaultValueProvider;
import picocli.CommandLine.ITypeConverter;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Model.ArgSpec;
import picocli.CommandLine.Model.PositionalParamSpec;

/**
 * Client basic command line configuration.
 * 
 * @since 2.3
 */
public class ClientBaseConfig extends ConnectorConfig {

	public static final String LABELT_URI = "URI";

	public static final String DEFAULT_URI = "californium.eclipseprojects.io";

	public String defaultUri = DEFAULT_URI;
	/**
	 * Default identity for PSK.
	 * 
	 * @see #setDefaultPskCredentials(String)
	 * @see #setDefaultPskCredentials(String, String)
	 */
	private String defaultIdentity;
	/**
	 * Default secret for PSK:
	 * 
	 * @see #setDefaultPskCredentials(String, String)
	 */
	private String defaultSecret;

	/**
	 * Proxy configuration.
	 */
	@Option(names = "--proxy", description = "use proxy. <address>:<port>[:<scheme>]. Default env-value of COAP_PROXY.")
	public ProxyConfiguration proxy;

	/**
	 * Local port.
	 */
	@Option(names = "--local-port", description = "local porty. Default ephemeral port.")
	public Integer localPort;

	/**
	 * Destination URI.
	 */
	@Parameters(index = "0", paramLabel = LABELT_URI, arity = "0..1", description = "destination URI. Default ${DEFAULT-VALUE}")
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
		final IDefaultValueProvider defaultValueProvider = cmd.getDefaultValueProvider();
		IDefaultValueProvider newDefaultValueProvider = new IDefaultValueProvider() {

			@Override
			public String defaultValue(ArgSpec argSpec) throws Exception {
				if (argSpec instanceof PositionalParamSpec) {
					PositionalParamSpec spec = (PositionalParamSpec) argSpec;
					if (LABELT_URI.contentEquals(spec.paramLabel())) {
						return defaultUri;
					}
				}
				return defaultValueProvider != null ? defaultValueProvider.defaultValue(argSpec) : null;
			}

		};
		cmd.setDefaultValueProvider(newDefaultValueProvider);
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
		String scheme = CoAP.getSchemeFromUri(uri);
		if (scheme == null) {
			if (authenticationModes.isEmpty()) {
				uri = CoAP.COAP_URI_SCHEME + "://" + uri;
			} else {
				uri = CoAP.COAP_SECURE_URI_SCHEME + "://" + uri;
				secure = true;
			}
		} else {
			secure = CoAP.isSecureScheme(scheme);
			tcp = CoAP.isTcpScheme(scheme);
		}
		if (uri.endsWith("/")) {
			uri = uri.substring(uri.length() - 1);
		}
		if (secure) {
			if (tcp) {
				if (trust == null) {
					trust = new Trust();
				}
				if (trust.trusts == null) {
					if (trust.trustall) {
						trust.trusts = new Certificate[0];
					} else {
						try {
							trust.trusts = SslContextUtil.loadTrustedCertificates(defaultEcTrusts);
						} catch (GeneralSecurityException e) {
							e.printStackTrace();
						} catch (IOException e) {
							e.printStackTrace();
						}
					}
				}
				if (authentication == null) {
					authentication = new Authentication();
				}
				if (!authentication.anonymous && authentication.credentials == null) {
					try {
						authentication.credentials = SslContextUtil.loadCredentials(defaultEcCredentials);
					} catch (GeneralSecurityException e) {
						e.printStackTrace();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
				if (authenticationModes.isEmpty()) {
					authenticationModes.add(AuthenticationMode.X509);
				}
			} else if (authenticationModes.isEmpty() || authenticationModes.contains(AuthenticationMode.PSK)
					|| authenticationModes.contains(AuthenticationMode.ECDHE_PSK)) {
				if (identity == null && secret == null) {
					identity = defaultIdentity;
					secret = new ConnectorConfig.Secret();
					secret.text = defaultSecret;
					if (authenticationModes.isEmpty()) {
						authenticationModes.add(AuthenticationMode.PSK);
					}
				}
			}
		}
	}

	/**
	 * Create client configuration clone with different PSK identity and secret.
	 * 
	 * @param id psk identity
	 * @param secret secret. if {@code null} and
	 *            {@link ConnectorConfig#PSK_IDENTITY_PREFIX} is used, use
	 *            {@link ConnectorConfig#PSK_SECRET}
	 * @return create client configuration clone.
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
	 * Create client configuration clone with different ec key pair.
	 * 
	 * @param privateKey private key
	 * @param publicKey public key
	 * @return create client configuration clone.
	 */
	public ClientBaseConfig create(PrivateKey privateKey, PublicKey publicKey) {
		ClientBaseConfig clone = null;
		try {
			clone = (ClientBaseConfig) clone();
			clone.authentication = new Authentication();
			clone.authentication.credentials = new SslContextUtil.Credentials(privateKey, publicKey, null);
		} catch (CloneNotSupportedException e) {
			e.printStackTrace();
		}
		return clone;
	}

	/**
	 * Set default PSK credentials
	 * 
	 * @param identity default identity. If {@code null}, use
	 *            {@link #PSK_IDENTITY_PREFIX} as default.
	 * @param secret default secret. If {@code null}, use {@link #PSK_SECRET} as
	 *            default.
	 */
	public void setDefaultPskCredentials(String identity, String secret) {
		defaultIdentity = identity;
		defaultSecret = secret;
	}

	/**
	 * Set default PSK credentials
	 * 
	 * @param identity default identity. If {@code null}, use
	 *            {@link #PSK_IDENTITY_PREFIX} as default.
	 * @since 2.4
	 */
	public void setDefaultPskCredentials(String identity) {
		defaultIdentity = PSK_IDENTITY_PREFIX + identity;
		defaultSecret = null;
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
