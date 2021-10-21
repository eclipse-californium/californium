/*******************************************************************************
 * Copyright (c) 2017, 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add ETSI credentials
 *    Achim Kraus (Bosch Software Innovations GmbH) - make added endpoints more selectable
 ******************************************************************************/
package org.eclipse.californium.plugtests;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.config.CoapConfig.MatcherMode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.elements.PrincipalEndpointContextMatcher;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.IntegerDefinition;
import org.eclipse.californium.elements.config.TcpConfig;
import org.eclipse.californium.elements.config.TimeDefinition;
import org.eclipse.californium.elements.tcp.netty.TcpServerConnector;
import org.eclipse.californium.elements.tcp.netty.TlsServerConnector;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.plugtests.PlugtestServer.BaseConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.MdcConnectionListener;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedPskStore;
import org.eclipse.californium.scandium.dtls.pskstore.AsyncAdvancedPskStore;
import org.eclipse.californium.scandium.dtls.resumption.AsyncResumptionVerifier;
import org.eclipse.californium.scandium.dtls.x509.AsyncKeyManagerCertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.AsyncNewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * Base for test servers.
 */
public abstract class AbstractTestServer extends CoapServer {

	public enum Protocol {
		UDP, DTLS, TCP, TLS
	}

	public enum InterfaceType {
		LOCAL, EXTERNAL, IPV4, IPV6,
	}

	public static class Select {
		public final Protocol protocol;
		public final InterfaceType interfaceType;

		public Select(Protocol protocol) {
			this.protocol = protocol;
			this.interfaceType = null;
		}

		public Select(InterfaceType interfaceType) {
			this.protocol = null;
			this.interfaceType = interfaceType;
		}

		public Select(Protocol protocol, InterfaceType interfaceType) {
			this.protocol = protocol;
			this.interfaceType = interfaceType;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((interfaceType == null) ? 0 : interfaceType.hashCode());
			result = prime * result + ((protocol == null) ? 0 : protocol.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			Select other = (Select) obj;
			if (interfaceType != other.interfaceType)
				return false;
			if (protocol != other.protocol)
				return false;
			return true;
		}
	}

	// exit codes for runtime errors
	private static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	private static final char[] TRUST_STORE_PASSWORD = "rootPass".toCharArray();
	private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";
	private static final String SERVER_NAME = "server";
	private static final String PSK_IDENTITY_PREFIX = "cali.";
	private static final SecretKey PSK_SECRET = SecretUtil.create(".fornium".getBytes(), "PSK");

	// from ETSI Plugtest test spec
	public static final String ETSI_PSK_IDENTITY = "password";
	public static final SecretKey ETSI_PSK_SECRET = SecretUtil.create("sesame".getBytes(), "PSK");

	// easier testing with openssl clients
	public static final String OPENSSL_PSK_IDENTITY = "Client_identity";
	public static final SecretKey OPENSSL_PSK_SECRET = SecretUtil.create("secretPSK".getBytes(), "PSK");

	public static final TimeDefinition DTLS_HANDSHAKE_RESULT_DELAY = new TimeDefinition("DTLS_HANDSHAKE_RESULT_DELAY",
			"Delay for DTLS handshake results. Only for testing!!!\n0 no delay, < 0 blocking delay, > 0 non-blocking delay.");

	public static final Pattern HONO_IDENTITY_PATTERN = Pattern.compile("^[^@]{8,}@.{8,}$");
	public static final SecretKey HONO_PSK_SECRET = SecretUtil.create("secret".getBytes(), "PSK");

	public static final Pattern IPV6_SCOPE = Pattern.compile("^([0-9a-fA-F:]+)(%\\w+)?$");
	/**
	 * Preferred blocksize when using coap/UDP on external interface.
	 * 
	 * Small value to prevent amplification.
	 */
	public static final IntegerDefinition EXTERNAL_UDP_PREFERRED_BLOCK_SIZE = new IntegerDefinition("EXTERNAL_UDP_PREFERRED_BLOCK_SIZE",
			"Preferred blocksize for blockwise transfer with coap/UDP using an external network interface.", 64, 16);

	/**
	 * Maximum payload size before using blockwise when using coap/UDP on external interface.
	 * 
	 * Small value to prevent amplification.
	 */
	public static final IntegerDefinition EXTERNAL_UDP_MAX_MESSAGE_SIZE = new IntegerDefinition("EXTERNAL_UDP_MAX_MESSAGE_SIZE",
			"Maximum payload size with coap/UDP using an external network interface.", 64, 16);

	private final Configuration config;
	private final Map<Select, Configuration> selectConfig;

	private AtomicBoolean loadCredentials = new AtomicBoolean(true);
	protected KeyManager[] serverCredentials = null;
	protected Certificate[] trustedCertificates = null;
	protected SSLContext serverSslContext = null;

	protected AbstractTestServer(Configuration config, Map<Select, Configuration> selectConfig) {
		super(config);
		this.config = config;
		this.selectConfig = selectConfig;
	}

	public Configuration getConfig(Select select) {
		if (selectConfig != null) {
			Configuration udpConfig = selectConfig.get(select);
			if (udpConfig != null) {
				return udpConfig;
			}
		}
		return config;
	}

	public Configuration getConfig(Protocol protocol, InterfaceType interfaceType) {
		if (selectConfig != null) {
			Select select = new Select(protocol, interfaceType);
			Configuration udpConfig = selectConfig.get(select);
			if (udpConfig != null) {
				return udpConfig;
			}
			select = new Select(protocol);
			udpConfig = selectConfig.get(select);
			if (udpConfig != null) {
				return udpConfig;
			}
			select = new Select(interfaceType);
			udpConfig = selectConfig.get(select);
			if (udpConfig != null) {
				return udpConfig;
			}
		}
		return config;
	}

	/**
	 * Initialize x509 credentials.
	 * 
	 * @since 2.5
	 */
	protected void initCredentials() {
		if (loadCredentials.compareAndSet(true, false)) {
			try {
				serverCredentials = SslContextUtil.loadKeyManager(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION,
						"server.*", KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
				trustedCertificates = SslContextUtil.loadTrustedCertificates(
						SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, null, TRUST_STORE_PASSWORD);
				return;
			} catch (GeneralSecurityException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	protected SSLContext getServerSslContext(boolean trustAll, String protocol) {
		initCredentials();
		try {
			if (serverCredentials != null) {
				TrustManager[] trustManager;
				if (trustAll) {
					trustManager = SslContextUtil.createTrustAllManager();
				} else {
					trustManager = SslContextUtil.createTrustManager(SERVER_NAME, trustedCertificates);
				}
				SSLContext sslContext = SSLContext.getInstance(protocol);
				sslContext.init(serverCredentials, trustManager, null);
				return sslContext;
			}
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Add endpoints.
	 * 
	 * @param selectAddress  list of regular expression to filter the endpoints by
	 *                       {@link InetAddress#getHostAddress()}. May be
	 *                       {@code null} or {@code empty}, if endpoints should not
	 *                       be filtered by their host address.
	 * @param interfaceTypes list of type to filter the endpoints. Maybe
	 *                       {@code null} or empty, if endpoints should not be
	 *                       filtered by type.
	 * @param protocols      list of protocols to create endpoints for.
	 * @param cliConfig      client cli-config.
	 */
	public void addEndpoints(List<String> selectAddress, List<InterfaceType> interfaceTypes, List<Protocol> protocols,
			BaseConfig cliConfig) {
		int coapPort = config.get(CoapConfig.COAP_PORT);
		int coapsPort = config.get(CoapConfig.COAP_SECURE_PORT);

		if (protocols.contains(Protocol.DTLS) || protocols.contains(Protocol.TLS)) {
			initCredentials();
			serverSslContext = getServerSslContext(cliConfig.trustall, SslContextUtil.DEFAULT_SSL_PROTOCOL);
			if (serverSslContext == null && protocols.contains(Protocol.TLS)) {
				throw new IllegalArgumentException("TLS not supported, credentials missing!");
			}
		}
		List<InetAddress> used = new ArrayList<>();
		for (InetAddress addr : NetworkInterfacesUtil.getNetworkInterfaces()) {
			if (used.contains(addr)) {
				continue;
			}
			if (interfaceTypes != null && !interfaceTypes.isEmpty()) {
				if (addr.isLoopbackAddress()) {
					if (!interfaceTypes.contains(InterfaceType.LOCAL)) {
						continue;
					}
				} else {
					if (!interfaceTypes.contains(InterfaceType.EXTERNAL)) {
						continue;
					}
				}
				if (addr instanceof Inet4Address) {
					if (!interfaceTypes.contains(InterfaceType.IPV4)) {
						continue;
					}
				} else if (addr instanceof Inet6Address) {
					if (!interfaceTypes.contains(InterfaceType.IPV6)) {
						continue;
					}
				}
			}
			if (selectAddress != null && !selectAddress.isEmpty()) {
				boolean found = false;
				String name = addr.getHostAddress();
				for (String filter : selectAddress) {
					if (name.matches(filter)) {
						found = true;
						break;
					}
				}
				if (!found && addr instanceof Inet6Address) {
					Matcher matcher = IPV6_SCOPE.matcher(name);
					if (matcher.matches()) {
						// apply filter also on interface name
						name = matcher.group(1) + "%" + ((Inet6Address) addr).getScopedInterface().getName();
						for (String filter : selectAddress) {
							if (name.matches(filter)) {
								found = true;
								break;
							}
						}
					}
				}
				if (!found) {
					continue;
				}
			}
			used.add(addr);

			InterfaceType interfaceType = addr.isLoopbackAddress() ? InterfaceType.LOCAL : InterfaceType.EXTERNAL;

			if (protocols.contains(Protocol.UDP) || protocols.contains(Protocol.TCP)) {
				InetSocketAddress bindToAddress = new InetSocketAddress(addr, coapPort);
				if (protocols.contains(Protocol.UDP)) {
					Configuration udpConfig = getConfig(Protocol.UDP, interfaceType);
					CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
					builder.setInetSocketAddress(bindToAddress);
					builder.setConfiguration(udpConfig);
					CoapEndpoint endpoint = builder.build();
					addEndpoint(endpoint);
					print(endpoint, interfaceType);
				}
				if (protocols.contains(Protocol.TCP)) {
					Configuration tcpConfig = getConfig(Protocol.TCP, interfaceType);
					TcpServerConnector connector = new TcpServerConnector(bindToAddress, tcpConfig);
					CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
					builder.setConnector(connector);
					builder.setConfiguration(tcpConfig);
					CoapEndpoint endpoint = builder.build();
					addEndpoint(endpoint);
					print(endpoint, interfaceType);
				}
			}
			if (protocols.contains(Protocol.DTLS) || protocols.contains(Protocol.TLS)) {
				InetSocketAddress bindToAddress = new InetSocketAddress(addr, coapsPort);
				if (protocols.contains(Protocol.DTLS)) {
					Configuration dtlsConfig = getConfig(Protocol.DTLS, interfaceType);
					int handshakeResultDelayMillis = dtlsConfig.getTimeAsInt(DTLS_HANDSHAKE_RESULT_DELAY, TimeUnit.MILLISECONDS);

					if (cliConfig.clientAuth != null) {
						dtlsConfig.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, cliConfig.clientAuth);
					}
					DtlsConnectorConfig.Builder dtlsConfigBuilder = DtlsConnectorConfig.builder(dtlsConfig);
					AsyncAdvancedPskStore asyncPskStore = new AsyncAdvancedPskStore(new PlugPskStore());
					asyncPskStore.setDelay(handshakeResultDelayMillis);
					dtlsConfigBuilder.setAdvancedPskStore(asyncPskStore);
					dtlsConfigBuilder.setAddress(bindToAddress);
					X509KeyManager keyManager = SslContextUtil.getX509KeyManager(serverCredentials);
					AsyncKeyManagerCertificateProvider certificateProvider = new AsyncKeyManagerCertificateProvider(keyManager,
							CertificateType.RAW_PUBLIC_KEY, CertificateType.X_509);
					certificateProvider.setDelay(handshakeResultDelayMillis);
					dtlsConfigBuilder.setCertificateIdentityProvider(certificateProvider);
					AsyncNewAdvancedCertificateVerifier.Builder verifierBuilder = AsyncNewAdvancedCertificateVerifier
							.builder();
					if (cliConfig.trustall) {
						verifierBuilder.setTrustAllCertificates();
					} else {
						verifierBuilder.setTrustedCertificates(trustedCertificates);
					}
					verifierBuilder.setTrustAllRPKs();
					AsyncNewAdvancedCertificateVerifier verifier = verifierBuilder.build();
					verifier.setDelay(handshakeResultDelayMillis);
					dtlsConfigBuilder.setAdvancedCertificateVerifier(verifier);
					AsyncResumptionVerifier resumptionVerifier = new AsyncResumptionVerifier();
					resumptionVerifier.setDelay(handshakeResultDelayMillis);
					dtlsConfigBuilder.setResumptionVerifier(resumptionVerifier);
					dtlsConfigBuilder.setConnectionListener(new MdcConnectionListener());
					DTLSConnector connector = new DTLSConnector(dtlsConfigBuilder.build());
					CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
					builder.setConnector(connector);
					if (MatcherMode.PRINCIPAL == dtlsConfig.get(CoapConfig.RESPONSE_MATCHING)) {
						builder.setEndpointContextMatcher(new PrincipalEndpointContextMatcher(true));
					}
					builder.setConfiguration(dtlsConfig);
					CoapEndpoint endpoint = builder.build();
					addEndpoint(endpoint);
					print(endpoint, interfaceType);
				}
				if (protocols.contains(Protocol.TLS) && serverSslContext != null) {
					Configuration tlsConfig = getConfig(Protocol.TLS, interfaceType);
					if (cliConfig.clientAuth != null) {
						tlsConfig.set(TcpConfig.TLS_CLIENT_AUTHENTICATION_MODE, cliConfig.clientAuth);
					}
					int maxPeers = tlsConfig.get(CoapConfig.MAX_ACTIVE_PEERS);
					int sessionTimeout = tlsConfig.getTimeAsInt(TcpConfig.TLS_SESSION_TIMEOUT, TimeUnit.SECONDS);
					SSLSessionContext serverSessionContext = serverSslContext.getServerSessionContext();
					if (serverSessionContext != null) {
						serverSessionContext.setSessionTimeout(sessionTimeout);
						serverSessionContext.setSessionCacheSize(maxPeers);
					}
					TlsServerConnector connector = new TlsServerConnector(serverSslContext, bindToAddress, tlsConfig);
					CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
					builder.setConnector(connector);
					builder.setConfiguration(tlsConfig);
					CoapEndpoint endpoint = builder.build();
					addEndpoint(endpoint);
					print(endpoint, interfaceType);
				}
			}
		}
	}

	protected void print(CoapEndpoint endpoint, InterfaceType interfaceType) {
		LOGGER.info("{}listen on {} ({}) max msg size: {}, block size: {}", getTag(), endpoint.getUri(), interfaceType,
				endpoint.getConfig().get(CoapConfig.MAX_MESSAGE_SIZE),
				endpoint.getConfig().get(CoapConfig.PREFERRED_BLOCK_SIZE));
	}

	public static class PlugPskStore implements AdvancedPskStore {

		private final PskPublicInformation identity = new PskPublicInformation(PSK_IDENTITY_PREFIX + "sandbox");

		private SecretKey getKey(String identity) {
			if (identity.startsWith(PSK_IDENTITY_PREFIX)) {
				return SecretUtil.create(PSK_SECRET);
			}
			if (identity.equals(ETSI_PSK_IDENTITY)) {
				return SecretUtil.create(ETSI_PSK_SECRET);
			}
			if (identity.equals(OPENSSL_PSK_IDENTITY)) {
				return SecretUtil.create(OPENSSL_PSK_SECRET);
			}
			if (HONO_IDENTITY_PATTERN.matcher(identity).matches()) {
				return SecretUtil.create(HONO_PSK_SECRET);
			}
			return null;
		}

		@Override
		public boolean hasEcdhePskSupported() {
			return true;
		}

		@Override
		public PskSecretResult requestPskSecretResult(ConnectionId cid, ServerNames serverName,
				PskPublicInformation identity, String hmacAlgorithm, SecretKey otherSecret, byte[] seed, boolean useExtendedMasterSecret) {
			SecretKey key = getKey(identity.getPublicInfoAsString());
			return new PskSecretResult(cid, identity, key);
		}

		@Override
		public PskPublicInformation getIdentity(InetSocketAddress peerAddress, ServerNames virtualHost) {
			return identity;
		}

		@Override
		public void setResultHandler(HandshakeResultHandler resultHandler) {
			//
		}
	}
}
