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
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointContextMatcherFactory.MatcherMode;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.elements.PrincipalEndpointContextMatcher;
import org.eclipse.californium.elements.tcp.netty.TcpServerConnector;
import org.eclipse.californium.elements.tcp.netty.TlsServerConnector;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.plugtests.PlugtestServer.BaseConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.MdcConnectionListener;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.MultiNodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.SingleNodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.AsyncInMemoryPskStore;
import org.eclipse.californium.scandium.dtls.pskstore.StringPskStore;
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

	public static final String KEY_DTLS_PSK_DELAY = "DTLS_PSK_STORE_DELAY";

	public static final Pattern HONO_IDENTITY_PATTERN = Pattern.compile("^[^@]{8,}@.{8,}$");
	public static final SecretKey HONO_PSK_SECRET = SecretUtil.create("secret".getBytes(), "PSK");

	private final NetworkConfig config;
	private final Map<Select, NetworkConfig> selectConfig;

	protected AbstractTestServer(NetworkConfig config, Map<Select, NetworkConfig> selectConfig) {
		super(config);
		this.config = config;
		this.selectConfig = selectConfig;
	}

	public NetworkConfig getConfig(Select select) {
		if (selectConfig != null) {
			NetworkConfig udpConfig = selectConfig.get(select);
			if (udpConfig != null) {
				return udpConfig;
			}
		}
		return config;
	}

	public NetworkConfig getConfig(Protocol protocol, InterfaceType interfaceType) {
		if (selectConfig != null) {
			Select select = new Select(protocol, interfaceType);
			NetworkConfig udpConfig = selectConfig.get(select);
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
	 * Add endpoints.
	 * 
	 * @param selectAddress regular expression to filter the endpoints by
	 *            {@link InetAddress#getHostAddress()}. May be {@code null} or
	 *            {@code ""}, if endpoints should not be filtered by their host
	 *            address.
	 * @param interfaceTypes list of type to filter the endpoints. Maybe
	 *            {@code null} or empty, if endpoints should not be filtered by
	 *            type.
	 * @param protocols list of protocols to create endpoints for.
	 * @param cliConfig client cli-config.
	 */
	public void addEndpoints(String selectAddress, List<InterfaceType> interfaceTypes, List<Protocol> protocols,
			BaseConfig cliConfig) {
		int coapPort = config.getInt(Keys.COAP_PORT);
		int coapsPort = config.getInt(Keys.COAP_SECURE_PORT);

		SslContextUtil.Credentials serverCredentials = null;
		Certificate[] trustedCertificates = null;
		SSLContext serverSslContext = null;

		if (protocols.contains(Protocol.DTLS) || protocols.contains(Protocol.TLS)) {
			try {
				serverCredentials = SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION,
						SERVER_NAME, KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
				trustedCertificates = SslContextUtil.loadTrustedCertificates(
						SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, null, TRUST_STORE_PASSWORD);

				KeyManager[] keyManager = SslContextUtil.createKeyManager(SERVER_NAME,
							serverCredentials.getPrivateKey(),
							serverCredentials.getCertificateChain());

				TrustManager[] trustManager;
				if (cliConfig.trustall) {
					trustManager = SslContextUtil.createTrustAllManager();
				} else {
					trustManager = SslContextUtil.createTrustManager(SERVER_NAME, trustedCertificates);
				}
				serverSslContext = SSLContext.getInstance(SslContextUtil.DEFAULT_SSL_PROTOCOL);
				serverSslContext.init(keyManager, trustManager, null);

			} catch (GeneralSecurityException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		for (InetAddress addr : NetworkInterfacesUtil.getNetworkInterfaces()) {
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
				if (!addr.getHostAddress().matches(selectAddress)) {
					continue;
				}
			}

			InterfaceType interfaceType = addr.isLoopbackAddress() ? InterfaceType.LOCAL : InterfaceType.EXTERNAL;

			if (protocols.contains(Protocol.UDP) || protocols.contains(Protocol.TCP)) {
				InetSocketAddress bindToAddress = new InetSocketAddress(addr, coapPort);
				if (protocols.contains(Protocol.UDP)) {
					NetworkConfig udpConfig = getConfig(Protocol.UDP, interfaceType);
					CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
					builder.setInetSocketAddress(bindToAddress);
					builder.setNetworkConfig(udpConfig);
					CoapEndpoint endpoint = builder.build();
					addEndpoint(endpoint);
					print(endpoint, interfaceType);
				}
				if (protocols.contains(Protocol.TCP)) {
					NetworkConfig tcpConfig =  getConfig(Protocol.TCP, interfaceType);
					int tcpThreads = tcpConfig.getInt(Keys.TCP_WORKER_THREADS);
					int tcpIdleTimeout = tcpConfig.getInt(Keys.TCP_CONNECTION_IDLE_TIMEOUT);
					TcpServerConnector connector = new TcpServerConnector(bindToAddress, tcpThreads, tcpIdleTimeout);
					CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
					builder.setConnector(connector);
					builder.setNetworkConfig(tcpConfig);
					CoapEndpoint endpoint = builder.build();
					addEndpoint(endpoint);
					print(endpoint, interfaceType);
				}
			}
			if (protocols.contains(Protocol.DTLS) || protocols.contains(Protocol.TLS)) {
				InetSocketAddress bindToAddress = new InetSocketAddress(addr, coapsPort);
				if (protocols.contains(Protocol.DTLS)) {
					NetworkConfig dtlsConfig = getConfig(Protocol.DTLS, interfaceType);
					int retransmissionTimeout = dtlsConfig.getInt(Keys.ACK_TIMEOUT);
					int staleTimeout = dtlsConfig.getInt(Keys.MAX_PEER_INACTIVITY_PERIOD);
					int dtlsThreads = dtlsConfig.getInt(Keys.NETWORK_STAGE_SENDER_THREAD_COUNT);
					int dtlsReceiverThreads = dtlsConfig.getInt(Keys.NETWORK_STAGE_RECEIVER_THREAD_COUNT);
					int maxPeers = dtlsConfig.getInt(Keys.MAX_ACTIVE_PEERS);
					Integer pskStoreDelay = dtlsConfig.getOptInteger(KEY_DTLS_PSK_DELAY);
					Integer cidLength = dtlsConfig.getOptInteger(Keys.DTLS_CONNECTION_ID_LENGTH);
					Integer cidNode = dtlsConfig.getOptInteger(Keys.DTLS_CONNECTION_ID_NODE_ID);
					Integer healthStatusInterval = config.getInt(NetworkConfig.Keys.HEALTH_STATUS_INTERVAL); // seconds
					Integer recvBufferSize = config.getOptInteger(Keys.UDP_CONNECTOR_RECEIVE_BUFFER);
					Integer sendBufferSize = config.getOptInteger(Keys.UDP_CONNECTOR_SEND_BUFFER);
					DtlsConnectorConfig.Builder dtlsConfigBuilder = new DtlsConnectorConfig.Builder();
					if (cidLength != null) {
						if (cidLength > 4 && cidNode != null) {
							dtlsConfigBuilder
									.setConnectionIdGenerator(new MultiNodeConnectionIdGenerator(cidNode, cidLength));
						} else {
							dtlsConfigBuilder.setConnectionIdGenerator(new SingleNodeConnectionIdGenerator(cidLength));
						}
					}
					if (pskStoreDelay != null) {
						dtlsConfigBuilder.setAdvancedPskStore(
								new AsyncInMemoryPskStore(new PlugPskStore()).setDelay(pskStoreDelay));
					} else {
						dtlsConfigBuilder.setPskStore(new PlugPskStore());
					}
					dtlsConfigBuilder.setAddress(bindToAddress);
					dtlsConfigBuilder.setRecommendedCipherSuitesOnly(false);
					dtlsConfigBuilder.setSupportedCipherSuites(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
							CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256,
							CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
							CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256,
							CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
							CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
					dtlsConfigBuilder.setIdentity(serverCredentials.getPrivateKey(), serverCredentials.getCertificateChain(),
							CertificateType.RAW_PUBLIC_KEY, CertificateType.X_509);
					if (cliConfig.trustall) {
						dtlsConfigBuilder.setTrustStore(new Certificate[0]);
					} else {
						dtlsConfigBuilder.setTrustStore(trustedCertificates);
					}
					dtlsConfigBuilder.setRpkTrustAll();
					dtlsConfigBuilder.setMaxConnections(maxPeers);
					dtlsConfigBuilder.setStaleConnectionThreshold(staleTimeout);
					dtlsConfigBuilder.setConnectionThreadCount(dtlsThreads);
					dtlsConfigBuilder.setReceiverThreadCount(dtlsReceiverThreads);
					dtlsConfigBuilder.setHealthStatusInterval(healthStatusInterval);
					dtlsConfigBuilder.setSocketReceiveBufferSize(recvBufferSize); 
					dtlsConfigBuilder.setSocketSendBufferSize(sendBufferSize); 
					dtlsConfigBuilder.setRetransmissionTimeout(retransmissionTimeout);
					switch(cliConfig.clientAuth) {
					case NONE:
						dtlsConfigBuilder.setClientAuthenticationRequired(false);
						break;
					case WANTED:
						dtlsConfigBuilder.setClientAuthenticationWanted(true);
						break;
					case NEEDED:
						dtlsConfigBuilder.setClientAuthenticationRequired(true);
						break;
					}
					dtlsConfigBuilder.setConnectionListener(new MdcConnectionListener());
					DTLSConnector connector = new DTLSConnector(dtlsConfigBuilder.build());
					CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
					builder.setConnector(connector);
					if (MatcherMode.PRINCIPAL.name().equals(dtlsConfig.getString(Keys.RESPONSE_MATCHING))) {
						builder.setEndpointContextMatcher(new PrincipalEndpointContextMatcher(true));
					}
					builder.setNetworkConfig(dtlsConfig);
					CoapEndpoint endpoint = builder.build();
					addEndpoint(endpoint);
					print(endpoint, interfaceType);
				}
				if (protocols.contains(Protocol.TLS)) {
					NetworkConfig tlsConfig = getConfig(Protocol.TLS, interfaceType);
					int tcpThreads = tlsConfig.getInt(Keys.TCP_WORKER_THREADS);
					int tcpIdleTimeout = tlsConfig.getInt(Keys.TCP_CONNECTION_IDLE_TIMEOUT);
					int tlsHandshakeTimeout = tlsConfig.getInt(Keys.TLS_HANDSHAKE_TIMEOUT);
					int maxPeers = tlsConfig.getInt(Keys.MAX_ACTIVE_PEERS);
					int sessionTimeout = tlsConfig.getInt(Keys.SECURE_SESSION_TIMEOUT);
					SSLSessionContext serverSessionContext = serverSslContext.getServerSessionContext();
					if (serverSessionContext != null) {
						serverSessionContext.setSessionTimeout(sessionTimeout);
						serverSessionContext.setSessionCacheSize(maxPeers);
					}
					TlsServerConnector connector = new TlsServerConnector(serverSslContext, cliConfig.clientAuth,
							bindToAddress, tcpThreads, tlsHandshakeTimeout, tcpIdleTimeout);
					CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
					builder.setConnector(connector);
					builder.setNetworkConfig(tlsConfig);
					CoapEndpoint endpoint = builder.build();
					addEndpoint(endpoint);
					print(endpoint, interfaceType);
				}
			}
		}
	}

	private void print(CoapEndpoint endpoint, InterfaceType interfaceType) {
		System.out.println("listen on " + endpoint.getUri() + " (" + interfaceType + ") max msg size: "
				+ endpoint.getConfig().getInt(Keys.MAX_MESSAGE_SIZE) + ", block: "
				+ endpoint.getConfig().getInt(Keys.PREFERRED_BLOCK_SIZE));
	}

	private static class PlugPskStore extends StringPskStore {

		@Override
		public SecretKey getKey(String identity) {
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
		public SecretKey getKey(ServerNames serverNames, String identity) {
			return getKey(identity);
		}

		@Override
		public String getIdentityAsString(InetSocketAddress inetAddress) {
			return PSK_IDENTITY_PREFIX + "sandbox";
		}

		@Override
		public String getIdentityAsString(InetSocketAddress peerAddress, ServerNames virtualHost) {
			return getIdentityAsString(peerAddress);
		}
	}
}
