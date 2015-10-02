/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - re-factor DTLSConnectorConfig into
 *                                               an immutable, provide a "builder" for easier
 *                                               instantiation/configuration
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add support for anonymous client-only
 *                                               configuration
 *******************************************************************************/

package org.eclipse.californium.scandium.config;

import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Arrays;

import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;

/**
 * A container for all configuration options of a <code>DTLSConnector</code>.
 * <p>
 * Instances of this class are immutable and can only be created by means of
 * the {@link Builder}, e.g.
 * <p>
 * <pre>
 * InetSocketAddress bindToAddress = new InetSocketAddress("localhost", 0); // use ephemeral port
 * DtlsConnectorConfig config = new DtlsConnectorConfig.Builder(bindToAddress)
 *    .setPskStore(new StaticPskStore("identity", "secret".getBytes()));
 *    .set... // additional configuration
 *    .build();
 * 
 * DTLSConnector connector = new DTLSConnector(config);
 * connector.start();
 * ...
 * </pre>
 */
public class DtlsConnectorConfig {

	private static final int MIN_PAYLOAD_SIZE = 60;
	private InetSocketAddress address;

	private Certificate[] trustStore = new Certificate[0];

	/**
	 * The maximum number of bytes to send in one datagram.
	 */
	private int maxPayloadSize = 0;

	/** The initial timer value for retransmission; rfc6347, section: 4.2.4.1 */
	private int retransmissionTimeout = 1000;

	/**
	 * Maximal number of retransmissions before the attempt to transmit a
	 * message is canceled
	 */
	private int maxRetransmissions = 4;

	/** does the server require the client to authenticate */
	private boolean clientAuthenticationRequired = true;

	/** do we send only the raw key (RPK) and not the full certificate (X509) */
	private boolean sendRawKey = true;

	/** store of the PSK */
	private PskStore pskStore = null;

	/** the private key for RPK and X509 mode */
	private PrivateKey privateKey = null;

	/** the public key for both RPK and X.509 mode */
	private PublicKey publicKey = null;

	/** the certificate for RPK and X509 mode */
	private Certificate[] certChain;

	/** the supported cipher suites in order of preference */
	private CipherSuite[] supportedCipherSuites;

	private int outboundMessageBufferSize = 100000;
	
	private DtlsConnectorConfig() {
		// empty
	}

	/**
	 * Gets the maximum number of bytes that can be sent to a peer within one record.
	 * 
	 * If this property is set to 0 (the default value), the <code>DTLSConnector</code>
	 * will determine its value according to the following formula:
	 * <pre>
	 * maxPayloadSize = Network Interface MTU size
	 *                    - 28 bytes (IP packet headers)
	 *                    - 13 bytes (record headers)
	 * </pre>
	 * 
	 * @return the maximum number of bytes
	 */
	public int getMaxPayloadSize() {
		return maxPayloadSize;
	}

	/**
	 * Gets the (intial) time to wait before a handshake flight of messages gets re-transmitted.
	 * 
	 * This timeout gets adjusted during the course of repeated re-transmission of a flight.
	 * The DTLS spec suggests an exponential back-off strategy, i.e. after each re-transmission the
	 * timeout value is doubled.
	 * 
	 * @return the (initial) time to wait in milliseconds
	 */
	public int getRetransmissionTimeout() {
		return retransmissionTimeout;
	}

	/**
	 * Gets the maximum number of times a flight of handshake messages gets re-transmitted
	 * to a peer.
	 * 
	 * @return the maximum number of re-transmissions
	 */
	public int getMaxRetransmissions() {
		return maxRetransmissions;
	}

	/**
	 * Gets the number of outbound messages that can be buffered in memory before
	 * messages are dropped.
	 * 
	 * @return the number of messages
	 */
	public int getOutboundMessageBufferSize() {
		return outboundMessageBufferSize;
	}
	
	/**
	 * Gets the IP address and port the connector is bound to.
	 * 
	 * @return the address
	 */
	public InetSocketAddress getAddress() {
		return address;
	}
	
	/**
	 * Gets the certificates forming the chain-of-trust from 
	 * a root CA down to the certificate asserting the server's identity.
	 * 
	 * @return the certificates or <code>null</code> if the connector is
	 * not supposed to support certificate based authentication
	 */
	public final Certificate[] getCertificateChain() {
		if (certChain == null) {
			return null;
		} else {
			return Arrays.copyOf(certChain, certChain.length);
		}
	}

	/**
	 * Gets the cipher suites the connector should advertise in a DTLS
	 * handshake.
	 * 
	 * @return the supported cipher suites (ordered by preference)
	 */
	public final CipherSuite[] getSupportedCipherSuites() {
		if (supportedCipherSuites == null) {
			return null;
		} else {
			return Arrays.copyOf(supportedCipherSuites, supportedCipherSuites.length);
		}
	}

	/**
	 * Gets the private key to use for proving identity to a peer
	 * during a DTLS handshake.
	 * 
	 * @return the key
	 */
	public final PrivateKey getPrivateKey() {
		return privateKey;
	}

	/**
	 * Gets the registry of <em>shared secrets</em> used for authenticating
	 * clients during a DTLS handshake.
	 * 
	 * @return the registry
	 */
	public final PskStore getPskStore() {
		return pskStore;
	}

	/**
	 * Gets the public key to send to peers during the DTLS handshake
	 * for authentication purposes.
	 * 
	 * @return the key
	 */
	public final PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Gets the trusted root certificates to use when verifying
	 * a peer's certificate during authentication.
	 * 
	 * @return the root certificates
	 */
	public final Certificate[] getTrustStore() {
		return trustStore;
	}

	/**
	 * Sets whether the connector requires DTLS clients to authenticate during
	 * the handshake.
	 * 
	 * @return <code>true</code> if clients need to authenticate
	 */
	public final boolean isClientAuthenticationRequired() {
		return clientAuthenticationRequired;
	}

	/**
	 * Checks whether the connector will send a <em>raw public key</em>
	 * instead of an X.509 certificate in order to authenticate to the peer
	 * during a DTLS handshake.
	 * 
	 * Note that this property is only relevant for cipher suites using certificate
	 * based authentication.
	 * 
	 * @return <code>true</code> if <em>RawPublicKey</em> is used by the connector
	 */
	public final boolean isSendRawKey() {
		return sendRawKey;
	}

	/**
	 * A helper for creating instances of <code>DtlsConnectorConfig</code>
	 * based on the builder pattern.
	 *
	 */
	public static final class Builder {
		
		private DtlsConnectorConfig config;
		private boolean clientOnly;
		
		/**
		 * Creates a new instance for setting configuration options
		 * for a <code>DTLSConnector</code> instance.
		 * 
		 * Once all options are set, clients should use the {@link #build()}
		 * method to create an immutable <code>DtlsConfigurationConfig</code>
		 * instance which can be passed into the <code>DTLSConnector</code>
		 * constructor.
		 * 
		 * The builder is initialized to the following default values
		 * <ul>
		 * <li><em>maxFragmentLength</em>: 4096 bytes</li>
		 * <li><em>maxPayloadSize</em>: 4096 + 25 bytes (max fragment size + 25 bytes for headers)</li>
		 * <li><em>maxRetransmissions</em>: 4</li>
		 * <li><em>retransmissionTimeout</em>: 1000ms</li>
		 * <li><em>clientAuthenticationRequired</em>: <code>true</code></li>
		 * <li><em>outboundMessageBufferSize</em>: 100.000</li>
		 * <li><em>trustStore</em>: empty array</li>
		 * </ul>
		 * 
		 * Note that when keeping the default values, at least one of the {@link #setPskStore(PskStore)}
		 * or {@link #setIdentity(PrivateKey, PublicKey)} methods need to be used to 
		 * get a working configuration for a <code>DTLSConnector</code> that can be used
		 * as a client and server.
		 * 
		 * It is possible to create a configuration for a <code>DTLSConnector</code> that can operate
		 * as a client only without the need for setting an identity. However, this is possible
		 * only if the server does not require clients to authenticate, i.e. this only
		 * works with the ECDH based cipher suites. If you want to create such a <em>client-only</em>
		 * configuration, you need to use the {@link #setClientOnly()} method on the builder.
		 * 
		 * @param address the IP address and port the connector should bind to
		 * @throws IllegalArgumentException if the given addess is unresolved
		 */
		public Builder(InetSocketAddress address) {
			if (address.isUnresolved()) {
				throw new IllegalArgumentException("Bind address must not be unresolved");
			}
			config = new DtlsConnectorConfig();
			config.address = address;
		}
		
		/**
		 * Indicates that the <em>DTLSConnector</em> will only be used as a
		 * DTLS client.
		 * 
		 * The {@link #build()} method will allow creation of a configuration
		 * without any identity being set under the following conditions:
		 * <ul>
		 * <li>only support for ECDH based cipher suites is configured</li>
		 * <li>this method has been invoked</li>
		 * </ul>
		 * 
		 * @return this builder for command chaining
		 */
		public Builder setClientOnly() {
			clientOnly = true;
			return this;
		}

		/**
		 * Sets the maximum number of bytes that can be sent to a peer within one UDP datagram
		 * excluding headers.
		 * <p>
		 * The value of this property is used when sending data to peers. Any DTLS record must fit
		 * into a single datagram. Thus, the value of this property limits the maximum length of
		 * any record's payload to <code>maxPayloadSize</code> - 13 (DTLS record headers) bytes.
		 * <p>
		 * The value of this property should be adjusted to the Path MTU in order
		 * to prevent IP fragmentation. Path MTU values are hard to know in advance
		 * and hard to come by during runtime as well. An good starting point might be
		 * using the following formula, though:
		 * <pre>
		 * maxPayloadSize = Network Interface MTU size
		 *                    - 20 bytes (IP headers)
		 *                    -  8 bytes (UDP headers)
		 * </pre>
		 * 
		 * If this property is set to 0 or not set at all, the <code>DTLSConnector</code> will
		 * determine its value exactly this way. In ethernet based environments the MTU size is
		 * usually around 1500 bytes resulting in a max. payload size of 1472 bytes and, consequently,
		 * a maximum record payload length of 1472 - 13 (DTLS record headers) = 1459 bytes.
		 * 
		 * @param size the number of bytes
		 * @return this builder for command chaining
		 * @throws IllegalArgumentException if size &ne; 0 and size &lt; 60 
		 */
		public Builder setMaxPayloadSize(int size) {
			if (size < 0 || (size > 0 && size < MIN_PAYLOAD_SIZE)) {
				throw new IllegalArgumentException("Maximum payload size must be at least " + MIN_PAYLOAD_SIZE + " bytes");
			} else {
				config.maxPayloadSize = size;
				return this;
			}
		}

		/**
		 * Sets the number of outbound messages that can be buffered in memory before
		 * dropping messages.
		 * 
		 * @param capacity the number of messages to buffer
		 * @return this builder for command chaining
		 * @throws IllegalArgumentException if capacity &lt; 1
		 */
		public Builder setOutboundMessageBufferSize(int capacity) {
			if (capacity < 1) {
				throw new IllegalArgumentException("Outbound message buffer size must be at least 1");
			} else {
				config.outboundMessageBufferSize = capacity;
				return this;
			}
		}
		
		/**
		 * Sets the maximum number of times a flight of handshake messages gets re-transmitted
		 * to a peer.
		 * 
		 * @param count the maximum number of re-transmissions
		 * @return this builder for command chaining
		 */
		public Builder setMaxRetransmissions(int count) {
			if (count < 1) {
				throw new IllegalArgumentException("Maximum number of retransmissions must be greater than zero");
			} else {
				config.maxRetransmissions = count;
				return this;
			}
		}
		
		/**
		 * Sets whether the connector requires DTLS clients to authenticate during
		 * the handshake.
		 * 
		 * @param authRequired
		 *            <code>true</code> if clients need to authenticate
		 * @return this builder for command chaining
		 */
		public Builder setClientAuthenticationRequired(boolean authRequired) {
			config.clientAuthenticationRequired = authRequired;
			return this;
		}
		
		/**
		 * Sets the cipher suites supported by the connector.
		 * <p>
		 * The connector will use these cipher suites (in exactly the same order) during
		 * the DTLS handshake when negotiating a cipher suite with a peer.
		 * 
		 * @param cipherSuites the supported cipher suites in the order of preference
		 * @return this builder for command chaining
		 * @throws IllegalArgumentException if the given array is <code>null</code>, is
		 *           empty or contains {@link CipherSuite#TLS_NULL_WITH_NULL_NULL}
		 */
		public Builder setSupportedCipherSuites(CipherSuite[] cipherSuites) {
			if (cipherSuites == null || cipherSuites.length == 0) {
				throw new IllegalArgumentException("Connector must support at least one cipher suite");
			} else {
				for (CipherSuite suite : cipherSuites) {
					if (CipherSuite.TLS_NULL_WITH_NULL_NULL.equals(suite)) {
						throw new IllegalArgumentException("NULL Cipher Suite is not supported by connector");
					}
				}
				config.supportedCipherSuites = Arrays.copyOf(cipherSuites, cipherSuites.length);
				return this;
			}
		}
		
		/**
		 * Sets the cipher suites supported by the connector.
		 * <p>
		 * The connector will use these cipher suites (in exactly the same order) during
		 * the DTLS handshake when negotiating a cipher suite with a peer.
		 * 
		 * @param cipherSuites the names of supported cipher suites in the order of preference
		 *     (see <a href="http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4">
		 *     IANA registry</a> for a list of cipher suite names)
		 * @return this builder for command chaining
		 * @throws IllegalArgumentException if the given array contains <em>TLS_NULL_WITH_NULL_NULL</em>
		 *     or if a name from the given list is unsupported (yet)  
		 */
		public Builder setSupportedCipherSuites(String[] cipherSuites) {
			CipherSuite[] suites = new CipherSuite[cipherSuites.length];
			for (int i = 0; i < cipherSuites.length; i++) {
				if (CipherSuite.TLS_NULL_WITH_NULL_NULL.name().equals(cipherSuites[i])) {
					throw new IllegalArgumentException("NULL Cipher Suite is not supported by connector");
				} else {
					CipherSuite knownSuite = CipherSuite.getTypeByName(cipherSuites[i]);
					if (knownSuite != null) {
						suites[i] = knownSuite;
					} else {
						throw new IllegalArgumentException(
								String.format("Cipher suite [%s] is not (yet) supported", cipherSuites[i]));
					}
				}
			}
			config.supportedCipherSuites = suites;
			return this;
		}
		
		/**
		 * Sets the time to wait before a handshake package gets re-transmitted.
		 * 
		 * @param timeout the time in milliseconds
		 * @return this builder for command chaining
		 * @throws IllegalArgumentException if the given timeout is negative
		 */
		public Builder setRetransmissionTimeout(int timeout) {
			if (timeout < 0) {
				throw new IllegalArgumentException("Retransmission timeout must not be negative");
			} else {
				config.retransmissionTimeout = timeout;
				return this;
			}
		}
		
		/**
		 * Sets the key store to use for authenticating clients based
		 * on a pre-shared key.
		 * 
		 * @param pskStore
		 *            the key store
		 * @return this builder for command chaining
		 */
		public Builder setPskStore(PskStore pskStore) {
			config.pskStore = pskStore;
			return this;
		}
		
		/**
		 * Sets the connector's identifying properties by means of a private
		 * and public key pair.
		 * <p>
		 * Using this method implies that the connector <em>only</em> supports
		 * <em>RawPublicKey</em> mode for authenticating to a peer.
		 * 
		 * @param privateKey the private key used for creating signatures
		 * @param publicKey the public key a peer can use to verify possession of the private key
		 * @return this builder for command chaining
		 * @throws NullPointerException if any of the given keys is <code>null</code>
		 */
		public Builder setIdentity(PrivateKey privateKey, PublicKey publicKey) {
			if (privateKey == null)
				throw new NullPointerException("The private key must not be null");
			if (publicKey == null)
				throw new NullPointerException("The public key must not be null");
			config.privateKey = privateKey;
			config.publicKey = publicKey;
			config.certChain = null;
			config.sendRawKey = true;
			return this;
		}
		
		/**
		 * Sets the connector's identifying properties by means of a private key
		 * and a corresponding issuer certificates chain.
		 * <p>
		 * In server mode the key and certificates are used to prove the server's
		 * identity to the client. In client mode the key and certificates are used
		 * to prove the client's identity to the server.
		 * 
		 * @param privateKey
		 *            the private key used for creating signatures
		 * @param certificateChain
		 *            the chain of certificates asserting the private key subject's
		 *            identity
		 * @param preferRawPublicKeys
		 *            <code>true</code> if the connector should indicate preference for
		 *            using <em>RawPublicKey</em>s for authentication purposes in the 
		 *            handshake with a peer (instead of including the full X.509 certificate chain)
		 * @return this builder for command chaining
		 * @throws NullPointerException if the given private key or certificate chain is <code>null</code>
		 *            or the certificate chain does not contain any certificates 
		 * @see #setIdentity(PrivateKey, PublicKey) for configuring <em>RawPublicKey</em>
		 *            mode only
		 */
		public Builder setIdentity(PrivateKey privateKey, Certificate[] certificateChain,
				boolean preferRawPublicKeys) {
			if (privateKey == null)
				throw new NullPointerException("The private key must not be null");
			if (certificateChain == null || certificateChain.length < 1)
				throw new NullPointerException("The certificate chain must not be null or empty");
			config.privateKey = privateKey;
			config.certChain = certificateChain;
			config.publicKey =  certificateChain[0].getPublicKey();
			config.sendRawKey = preferRawPublicKeys;
			return this;
		}
		
		/**
		 * Sets the root certificates the connector should use as the trust anchor when verifying
		 * a peer's identity based on an X.509 certificate chain.
		 * 
		 * @param trustedCerts the trusted root certificates
		 * @return this builder for command chaining
		 * @throws NullPointerException if the given array is <code>null</code>
		 */
		public Builder setTrustStore(Certificate[] trustedCerts) {
			if (trustedCerts == null) {
				throw new NullPointerException("Trust store must not be null");
			} else {
				config.trustStore = trustedCerts;
				return this;
			}
		}
		
		/**
		 * Creates an instance of <code>DtlsConnectorConfig</code> based on the properties
		 * set on this builder.
		 * <p>
		 * If the <em>supportedCipherSuites</em> property has not been set, the
		 * builder tries to derive a reasonable set of cipher suites from the
		 * <em>pskStore</em> and <em>identity</em> properties as follows:
		 * <ol>
		 * <li>If only the <em>pskStore</em> is set: <code>{TLS_PSK_WITH_AES_128_CCM_8,
		 * TLS_PSK_WITH_AES_128_CBC_SHA256}</code></li>
		 * <li>If only the <em>identity</em> is set: <code>{TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
		 * TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256}</code></li>
		 * <li>If both the <em>pskStore</em> and the <em>identity</em> are set:
		 * <code>{TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		 * TLS_PSK_WITH_AES_128_CCM_8, TLS_PSK_WITH_AES_128_CBC_SHA256}</code></li>
		 * </ol>
		 * 
		 * @return the configuration object
		 * @throws IllegalStateException if the configuration is inconsistent
		 */
		public DtlsConnectorConfig build() {
			if (config.supportedCipherSuites == null) {
				// user has not explicitly set cipher suites
				// try to guess his intentions from properties he has set
				if (config.pskStore != null && config.privateKey == null && config.publicKey == null) {
					
					config.supportedCipherSuites = 
							new CipherSuite[]{
								CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
								CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256};
					
				} else if (config.pskStore == null && config.privateKey != null && config.publicKey != null) {
					
					config.supportedCipherSuites =
							new CipherSuite[]{
								CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
								CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256};
					
				} else if (config.pskStore != null && config.privateKey != null && config.publicKey != null) {
					
					config.supportedCipherSuites = new CipherSuite[]{
							CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
							CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
							CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
							CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256};
					
				} else {
					throw new IllegalStateException("Supported cipher suites must be set either " +
							"explicitly or implicitly by means of setting the identity or PSK store");
				}
			}
			
			for (CipherSuite suite : config.supportedCipherSuites) {
				switch (suite) {
				case TLS_PSK_WITH_AES_128_CCM_8:
				case TLS_PSK_WITH_AES_128_CBC_SHA256:
					if (config.pskStore == null) {
						throw new IllegalStateException("PSK store must be set when support for " +
								CipherSuite.TLS_PSK_WITH_AES_128_CCM_8.name() + " is configured");
					}
					break;
				case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
				case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
					if (!clientOnly) {
						if (config.getPrivateKey() == null || config.getPublicKey() == null) {
							throw new IllegalStateException("Identity must be set");
						} else if (!(config.privateKey.getAlgorithm().equals("EC")) ||
								!(config.getPublicKey().getAlgorithm().equals("EC"))) {
							// test if private & public key are ECDSA capable
							throw new IllegalStateException("Keys must be ECDSA capable when support for an " +
									"ECDHE_ECDSA based cipher suite is configured");
						}
					}
					break;
				default:
					break;
				}
			}

			if (config.maxPayloadSize == 0) {
				// determine max payload size based on network interface's MTU
				try {
					NetworkInterface ni = NetworkInterface.getByInetAddress(config.address.getAddress());
					config.maxPayloadSize = ni.getMTU()
							- 20 // IP headers
							- 8; // UDP headers
				} catch (SocketException e) {
					throw new IllegalStateException("Cannot bind to address " + config.address);
				}
			}
			return config;
		}
	}
}
