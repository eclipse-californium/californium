/*******************************************************************************
 * Copyright (c) 2015 - 2017 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 483559
 *    Achim Kraus (Bosch Software Innovations GmbH) - add enable address reuse
 *    Ludwig Seitz (RISE SICS) - Added support for raw public key validation
 *    Achim Kraus (Bosch Software Innovations GmbH) - include trustedRPKs in
 *                                                    determineCipherSuitesFromConfig
 *    Achim Kraus (Bosch Software Innovations GmbH) - add automatic resumption
 *    Achim Kraus (Bosch Software Innovations GmbH) - issue #549
 *                                                    trustStore := null, disable x.509
 *                                                    trustStore := [], enable x.509, trust all
 *    Bosch Software Innovations GmbH - remove serverNameResolver property
 *    Vikram (University of Rostock) - added CipherSuite TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
 *    Achim Kraus (Bosch Software Innovations GmbH) - add multiple receiver threads.
 *                                                    move default thread numbers to this configuration.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add deferred processed messages
 *******************************************************************************/

package org.eclipse.californium.scandium.config;

import java.net.InetSocketAddress;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.dtls.rpkstore.TrustAllRpks;
import org.eclipse.californium.scandium.dtls.rpkstore.TrustedRpkStore;
import org.eclipse.californium.scandium.dtls.x509.CertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.StaticCertificateVerifier;

/**
 * A container for all configuration options of a <code>DTLSConnector</code>.
 * <p>
 * Instances of this class are immutable and can only be created by means of
 * the {@link Builder}, e.g.
 * </p>
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
public final class DtlsConnectorConfig {

	/**
	 * The default value for the <em>maxDeferredProcessedApplicationDataMessages</em> property.
	 */
	public static final int DEFAULT_MAX_DEFERRED_PROCESSED_APPLICATION_DATA_MESSAGES = 10;
	/**
	 * The default value for the <em>maxConncetions</em> property.
	 */
	public static final int DEFAULT_MAX_CONNECTIONS = 150000;
	/**
	 * The default value for the <em>staleConnectionThreshold</em> property.
	 */
	public static final long DEFAULT_STALE_CONNECTION_TRESHOLD = 30 * 60; // 30 minutes
	/**
	 * The default size of the executor's thread pool which is used for processing records.
	 * <p>
	 * The value of this property is 6 * <em>#(CPU cores)</em>.
	 */
	private static final int DEFAULT_EXECUTOR_THREAD_POOL_SIZE = 6 * Runtime.getRuntime().availableProcessors();
	/**
	 * The default number of receiver threads.
	 * <p>
	 * The value of this property is (<em>#(CPU cores)</em> + 1) / 2.
	 */
	private static final int DEFAULT_RECEIVER_THREADS = (Runtime.getRuntime().availableProcessors() + 1) / 2;

	private static final String EC_ALGORITHM_NAME = "EC";

	private InetSocketAddress address;
	private X509Certificate[] trustStore;
	private CertificateVerifier certificateVerifier;

	/**
	 * Experimental feature : Stop retransmission at message receipt
	 */
	private Boolean earlyStopRetransmission;

	/**
	 * Enable to reuse the address.
	 */
	private Boolean enableReuseAddress;

	/**
	 * The maximum fragment length this connector can process at once.
	 */
	private Integer maxFragmentLengthCode;

	/** The initial timer value for retransmission; rfc6347, section: 4.2.4.1 */
	private Integer retransmissionTimeout;

	/**
	 * Maximal number of retransmissions before the attempt to transmit a
	 * message is canceled.
	 */
	private Integer maxRetransmissions;

	/**
	 * Maximum transmission unit.
	 */
	private Integer maxTransmissionUnit;

	/** does the server require the client to authenticate */
	private Boolean clientAuthenticationRequired;

	/** do we send only the raw key (RPK) and not the full certificate (X509) */
	private Boolean sendRawKey;

	/** store of the PSK */
	private PskStore pskStore;

	/** the private key for RPK and X509 mode, right now only EC type is supported */
	private PrivateKey privateKey;

	/** the public key for RPK and X.509 mode, right now only EC type is supported */
	private PublicKey publicKey;

	/** the certificate for RPK and X509 mode */
	private X509Certificate[] certChain;

	/** the supported cipher suites in order of preference */
	private CipherSuite[] supportedCipherSuites;

	/** default is trust all RPKs **/
	private TrustedRpkStore trustedRPKs;

	private Integer outboundMessageBufferSize;

	private Integer maxDeferredProcessedApplicationDataMessages;

	private Integer maxConnections;

	private Long staleConnectionThreshold;

	private Integer connectionThreadCount;

	private Integer receiverThreadCount;

	/**
	 * Automatic session resumption timeout. Triggers session resumption
	 * automatically, if no messages are exchanged for this timeout. Intended to
	 * be used, if traffic is routed through a NAT. If {@code null}, no
	 * automatic session resumption is used. Value is in milliseconds.
	 */
	private Long autoResumptionTimeoutMillis;

	private Boolean sniEnabled;

	/**
	 * Use HELLO_VERIFY_REQUEST for session resumption.
	 */
	private Boolean verifyRequestOnResumptionEnabled;

	private DtlsConnectorConfig() {
		// empty
	}

	/**
	 * Gets the maximum amount of message payload data that this connector can receive in a
	 * single DTLS record.
	 * <p>
	 * The code returned is either <code>null</code> or one of the following:
	 * <ul>
	 * <li>1 - 2^9 bytes</li>
	 * <li>2 - 2^10 bytes</li>
	 * <li>3 - 2^11 bytes</li>
	 * <li>4 - 2^12 bytes</li>
	 * </ul>
	 * 
	 * @return the code indicating the maximum payload length
	 */
	public Integer getMaxFragmentLengthCode() {
		return maxFragmentLengthCode;
	}

	/**
	 * Gets the (initial) time to wait before a handshake flight of messages gets re-transmitted.
	 * 
	 * This timeout gets adjusted during the course of repeated re-transmission of a flight.
	 * The DTLS spec suggests an exponential back-off strategy, i.e. after each re-transmission the
	 * timeout value is doubled.
	 * 
	 * @return the (initial) time to wait in milliseconds
	 */
	public Integer getRetransmissionTimeout() {
		return retransmissionTimeout;
	}

	/**
	 * Gets the maximum number of deferred processed application data messages.
	 * 
	 * @return the maximum number of deferred processed application data messages
	 */
	public Integer getMaxDeferredProcessedApplicationDataMessages() {
		return maxDeferredProcessedApplicationDataMessages;
	}

	/**
	 * Gets the maximum number of times a flight of handshake messages gets re-transmitted
	 * to a peer.
	 * 
	 * @return the maximum number of re-transmissions
	 */
	public Integer getMaxRetransmissions() {
		return maxRetransmissions;
	}

	/**
	 * Gets the maximum transmission unit.
	 * 
	 * Maximum number of bytes sent in one transmission.
	 * 
	 * @return maximum transmission unit
	 */
	public Integer getMaxTransmissionUnit() {
		return maxTransmissionUnit;
	}

	/**
	 * @return true if retransmissions should be stopped as soon as we receive
	 *         handshake message
	 */
	public Boolean isEarlyStopRetransmission() {
		return earlyStopRetransmission;
	}

	/**
	 * @return true, if address reuse should be enabled for the socket. 
	 */
	public Boolean isAddressReuseEnabled() {
		return enableReuseAddress;
	}

	/**
	 * Checks whether the connector should support the use of the TLS
	 * <a href="https://tools.ietf.org/html/rfc6066#section-3">
	 * Server Name Indication extension</a> in the DTLS handshake.
	 * <p>
	 * The default value of this property is {@code null}. If this property
	 * is not set explicitly using {@link Builder#setSniEnabled(boolean)},
	 * then the {@link Builder#build()} method will set it to {@code true}.
	 * 
	 * @return {@code true} if SNI should be used.
	 */
	public Boolean isSniEnabled() {
		return sniEnabled;
	}

	/**
	 * Checks whether a HELLO_VERIFY_REQUEST should be used also for session
	 * resumption. Though a CLIENT_HELLO with an session id is used for session
	 * resumption, that session ID could be used to check, if this is a valid
	 * CLIENT_HELLO request.
	 * 
	 * @return {@code true} if a HELLO_VERIFY_REQUEST should be used also for
	 *         session resumption
	 */
	public Boolean isVerifyRequestOnResumptionEnabled() {
		return verifyRequestOnResumptionEnabled;
	}

	/**
	 * Gets the number of outbound messages that can be buffered in memory before
	 * messages are dropped.
	 * 
	 * @return the number of messages
	 */
	public Integer getOutboundMessageBufferSize() {
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
	public X509Certificate[] getCertificateChain() {
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
	public CipherSuite[] getSupportedCipherSuites() {
		if (supportedCipherSuites == null) {
			return new CipherSuite[0];
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
	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	/**
	 * Gets the registry of <em>shared secrets</em> used for authenticating
	 * clients during a DTLS handshake.
	 * 
	 * @return the registry
	 */
	public PskStore getPskStore() {
		return pskStore;
	}

	/**
	 * Gets the public key to send to peers during the DTLS handshake
	 * for authentication purposes.
	 * 
	 * @return the key
	 */
	public PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Gets the trusted root certificates to use when verifying
	 * a peer's certificate during authentication.
	 * 
	 * @return the root certificates
	 */
	public X509Certificate[] getTrustStore() {
		return trustStore;
	}

	/**
	 * Gets the verifier in charge of validating the peer's certificate chain
	 * during the DTLS handshake.
	 *
	 * @return the certificate chain verifier
	 */
	public CertificateVerifier getCertificateVerifier() {
		return certificateVerifier;
	}

	/**
	 * Sets whether the connector requires DTLS clients to authenticate during
	 * the handshake.
	 * 
	 * @return <code>true</code> if clients need to authenticate
	 */
	public Boolean isClientAuthenticationRequired() {
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
	public Boolean isSendRawKey() {
		return sendRawKey;
	}

	/**
	 * Gets the maximum number of (active) connections the connector will support.
	 * <p>
	 * Once this limit is reached, new connections will only be accepted if <em>stale</em>
	 * connections exist. A stale connection is one that hasn't been used for at least
	 * <em>staleConnectionThreshold</em> seconds.
	 * 
	 * @return The maximum number of active connections supported.
	 * @see #getStaleConnectionThreshold()
	 */
	public Integer getMaxConnections() {
		return maxConnections;
	}

	/**
	 * Gets the maximum number of seconds within which some records need to be exchanged
	 * over a connection before it is considered <em>stale</em>.
	 * <p>
	 * Once a connection becomes stale, it cannot be used to transfer DTLS records anymore.
	 * 
	 * @return The number of seconds.
	 * @see #getMaxConnections()
	 */
	public Long getStaleConnectionThreshold() {
		return staleConnectionThreshold;
	}

	/**
	 * Gets the number of threads which should be use to handle DTLS connection.
	 * <p>
	 * The default value is 6 * <em>#(CPU cores)</em>.
	 * 
	 * @return the number of threads.
	 */
	public Integer getConnectionThreadCount() {
		return connectionThreadCount;
	}

	/**
	 * Gets the number of threads which should be use to receive datagrams
	 * from the socket.
	 * <p>
	 * The default value is half of <em>#(CPU cores)</em>.
	 * 
	 * @return the number of threads.
	 */
	public Integer getReceiverThreadCount() {
		return receiverThreadCount;
	}

	/**
	 * Get the timeout for automatic session resumption.
	 * 
	 * If no messages are exchanged for this timeout, the next message will
	 * trigger a session resumption automatically. Intended to be used, if
	 * traffic is routed over a NAT.
	 * 
	 * @return timeout in milliseconds, or {@code null}, if no automatic resumption
	 *         is intended.
	 */
	public Long getAutoResumptionTimeoutMillis() {
		return autoResumptionTimeoutMillis;
	}

	/**
	 * @return The trust store for raw public keys verified out-of-band for
	 *         DTLS-RPK handshakes
	 */
	public TrustedRpkStore getRpkTrustStore() {
		return trustedRPKs;
	}

	/**
	 * @return a copy of this configuration
	 */
	@Override
	protected Object clone() {
		DtlsConnectorConfig cloned = new DtlsConnectorConfig();
		cloned.address = address;
		cloned.trustStore = trustStore;
		cloned.certificateVerifier = certificateVerifier;
		cloned.earlyStopRetransmission = earlyStopRetransmission;
		cloned.enableReuseAddress = enableReuseAddress;
		cloned.maxFragmentLengthCode = maxFragmentLengthCode;
		cloned.retransmissionTimeout = retransmissionTimeout;
		cloned.maxRetransmissions = maxRetransmissions;
		cloned.maxTransmissionUnit = maxTransmissionUnit;
		cloned.clientAuthenticationRequired = clientAuthenticationRequired;
		cloned.sendRawKey = sendRawKey;
		cloned.pskStore = pskStore;
		cloned.privateKey = privateKey;
		cloned.publicKey = publicKey;
		cloned.certChain = certChain;
		cloned.supportedCipherSuites = supportedCipherSuites;
		cloned.trustedRPKs = trustedRPKs;
		cloned.outboundMessageBufferSize = outboundMessageBufferSize;
		cloned.maxDeferredProcessedApplicationDataMessages = maxDeferredProcessedApplicationDataMessages;
		cloned.maxConnections = maxConnections;
		cloned.staleConnectionThreshold = staleConnectionThreshold;
		cloned.connectionThreadCount = connectionThreadCount;
		cloned.autoResumptionTimeoutMillis = autoResumptionTimeoutMillis;
		cloned.sniEnabled = sniEnabled;
		cloned.verifyRequestOnResumptionEnabled = verifyRequestOnResumptionEnabled;
		return cloned;
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
		 * <li><em>address</em>: a wildcard address with a system chosen ephemeral port
		 *  see {@link InetSocketAddress#InetSocketAddress(int)}</li>
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
		 */
		public Builder() {
			config = new DtlsConnectorConfig();
		}
		
		/**
		 * Create a builder from an existing DtlsConnectorConfig.
		 * This allow to create a new config starting from values of another one.
		 */
		public Builder(DtlsConnectorConfig initalValues){
			config = (DtlsConnectorConfig) initalValues.clone();
		}

		/**
		 * Sets the IP address and port the connector should bind to
		 * 
		 * @param address the IP address and port the connector should bind to
		 * @return this builder for command chaining
		 * @throws IllegalArgumentException if the given address is unresolved
		 */
		public Builder setAddress(InetSocketAddress address) {
			if (address.isUnresolved()) {
				throw new IllegalArgumentException("Bind address must not be unresolved");
			}
			config.address = address;
			return this;
		}

		/**
		 * Enables address reuse for the socket.
		 * 
		 * @param enable {@code true} if addresses should be reused.
		 * @return this builder for command chaining
		 */
		public Builder setEnableAddressReuse(boolean enable) {
			config.enableReuseAddress = enable;
			return this;
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
		 * Sets the maximum amount of payload data that can be received and processed by this connector
		 * in a single DTLS record.
		 * <p>
		 * The value of this property is used to indicate to peers the <em>Maximum Fragment Length</em>
		 * as defined in <a href="http://tools.ietf.org/html/rfc6066#section-4">RFC 6066, Section 4</a>.
		 * It is also used to determine the amount of memory that will be allocated for receiving UDP datagrams
		 * sent by peers from the network interface.
		 * </p>
		 * The code must be either <code>null</code> or one of the following:
		 * <ul>
		 * <li>1 - 2^9 bytes</li>
		 * <li>2 - 2^10 bytes</li>
		 * <li>3 - 2^11 bytes</li>
		 * <li>4 - 2^12 bytes</li>
		 * </ul>
		 * <p>
		 * If this property is set to <code>null</code>, the <code>DTLSConnector</code> will
		 * derive its value from the network interface's <em>Maximum Transmission Unit</em>.
		 * This means that it will set it to a value small enough to make sure that inbound
		 * messages fit into a UDP datagram having a size less or equal to the MTU.
		 * </p>
		 * 
		 * @param lengthCode the code indicating the maximum length or <code>null</code> to determine
		 *                   the maximum fragment length based on the network interface's MTU
		 * @return this builder for command chaining
		 * @throws IllegalArgumentException if the code is not one of {1, 2, 3, 4} 
		 */
		public Builder setMaxFragmentLengthCode(Integer lengthCode) {
			if (lengthCode != null && (lengthCode < 1 || lengthCode > 4)) {
				throw new IllegalArgumentException("Maximum fragment length code must be one of {1, 2, 3, 4}");
			} else {
				config.maxFragmentLengthCode = lengthCode;
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
		 * Set maximum transmission unit. Maximum number of bytes sent in one
		 * transmission.
		 * 
		 * @param mtu maximum transmission unit
		 * @return this builder for command chaining
		 */
		public Builder setMaxTransmissionUnit(int mtu) {
			config.maxTransmissionUnit = mtu;
			return this;
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
		 * Activate/Deactivate experimental feature : Stop retransmission at message receipt.
		 * 
		 * @param activate Set it to true if retransmissions should be stopped as soon as we receive
		 *         handshake message
		 * @return this builder for command chaining
		 */
		public Builder setEarlyStopRetransmission(boolean activate) {
			config.earlyStopRetransmission = activate;
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
		 *            the chain of X.509 certificates asserting the private key subject's
		 *            identity
		 * @param preferRawPublicKeys
		 *            <code>true</code> if the connector should indicate preference for
		 *            using <em>RawPublicKey</em>s for authentication purposes in the 
		 *            handshake with a peer (instead of including the full X.509 certificate chain)
		 * @return this builder for command chaining
		 * @throws NullPointerException if the given private key or certificate chain is <code>null</code>
		 *            or the certificate chain does not contain any certificates
		 * @throws IllegalArgumentException if the certificate chain contains a non-X.509 certificate
		 * @see #setIdentity(PrivateKey, PublicKey) for configuring <em>RawPublicKey</em>
		 *            mode only
		 */
		public Builder setIdentity(PrivateKey privateKey, Certificate[] certificateChain,
				boolean preferRawPublicKeys) {
			if (privateKey == null) {
				throw new NullPointerException("The private key must not be null");
			} else if (certificateChain == null || certificateChain.length < 1) {
				throw new NullPointerException("The certificate chain must not be null or empty");
			} else {
				config.privateKey = privateKey;
				config.certChain = toX509Certificates(certificateChain);
				config.publicKey =  config.certChain[0].getPublicKey();
				config.sendRawKey = preferRawPublicKeys;
				return this;
			}
		}

		/**
		 * Sets the root certificates the connector should use:
		 * <ul>
		 * <li>as the trust anchor when verifying a peer's identity based on an
		 * X.509 certificate chain. This is default behavior, which can be
		 * overridden when passing a custom {@link CertificateVerifier} to this
		 * builder.</li>
		 * <li>as the list of certificate authorities when the server is
		 * requesting a client certificate during the DTLS handshake.</li>
		 * </ul>
		 * 
		 * @param trustedCerts the trusted root certificates
		 * @return this builder for command chaining
		 * @throws NullPointerException if the given array is <code>null</code>
		 * @throws IllegalArgumentException if the array contains a non-X.509
		 *             certificate
		 */
		public Builder setTrustStore(Certificate[] trustedCerts) {
			if (trustedCerts == null) {
				throw new NullPointerException("Trust store must not be null");
			} else {
				config.trustStore = toX509Certificates(trustedCerts);
				return this;
			}
		}

		/**
		 * Sets the logic in charge of validating a X.509 certificate chain.
		 * </br>
		 *
		 * Here are a few use cases where a custom implementation would be
		 * needed:
		 * <ul>
		 * <li>client certificate authentication based on a dynamic trusted CA
		 * <li>revocation not provided by the default implementation (e.g. OCSP)
		 * <li>cipher suites restriction per client
		 * </ul>
		 *
		 * @param verifier
		 * @return this builder for command chaining
		 */
		public Builder setCertificateVerifier(CertificateVerifier verifier) {
			if (verifier == null) {
				throw new NullPointerException("CertificateVerifier must not be null");
			} else {
				config.certificateVerifier = verifier;
				return this;
			}
		}

		/**
		 * Sets the store for trusted raw public keys.
		 * 
		 * @param store the rpk trust store
		 */
		public void setRpkTrustStore(TrustedRpkStore store) {
			if (store == null) {
				throw new IllegalStateException("Must provide a non-null rpk trust store");
			}
			config.trustedRPKs = store;
		}

		private static X509Certificate[] toX509Certificates(Certificate[] certs) {
			List<X509Certificate> result = new ArrayList<>(certs.length);
			for (Certificate cert : certs) {
				if (X509Certificate.class.isInstance(cert)) {
					result.add((X509Certificate) cert);
				} else {
					throw new IllegalArgumentException("can only process X.509 certificates");
				}
			}
			return result.toArray(new X509Certificate[certs.length]);
		}

		/**
		 * Set maximum number of deferred processed application data messages.
		 * 
		 * Application data messages received or sent during a handshake may be
		 * dropped or processed deferred after the handshake. Set this to limit
		 * the maximum number of messages, which are intended to be processed
		 * deferred. If more messages are sent or received, theses messages are
		 * dropped.
		 * 
		 * @param maxDeferredProcessedApplicationDataMessages maximum number of
		 *            deferred processed messages
		 * @return this builder for command chaining.
		 * @throws IllegalArgumentException if the given limit is &lt; 0.
		 */
		public Builder setMaxDeferredProcessedApplicationDataMessages(final int maxDeferredProcessedApplicationDataMessages) {
			if (maxDeferredProcessedApplicationDataMessages < 0) {
				throw new IllegalArgumentException("Max deferred processed application data messages must not be negative!");
			} else {
				config.maxDeferredProcessedApplicationDataMessages = maxDeferredProcessedApplicationDataMessages;
				return this;
			}
		}

		/**
		 * Sets the maximum number of active connections the connector should support.
		 * <p>
		 * An <em>active</em> connection is a connection that has been used within the
		 * last <em>staleConnectionThreshold</em> seconds. After that it is considered
		 * to be <em>stale</em>.
		 * <p>
		 * Once the maximum number of active connections is reached, new connections will
		 * only be accepted by the connector, if <em>stale</em> connections exist (which will
		 * be evicted one-by-one on an oldest-first basis).
		 * <p>
		 * The default value of this property is {@link DtlsConnectorConfig#DEFAULT_MAX_CONNECTIONS}.
		 * 
		 * @param maxConnections The maximum number of active connections to support.
		 * @return this builder for command chaining.
		 * @throws IllegalArgumentException if the given limit is &lt; 1.
		 * @see #setStaleConnectionThreshold(long)
		 */
		public Builder setMaxConnections(final int maxConnections) {
			if (maxConnections < 1) {
				throw new IllegalArgumentException("Max connections must be at least 1");
			} else {
				config.maxConnections = maxConnections;
				return this;
			}
		}

		/**
		 * Sets the maximum number of seconds without any data being exchanged before a connection
		 * is considered <em>stale</em>.
		 * <p>
		 * Once a connection becomes stale, it is eligible for eviction when a peer wants to establish a
		 * new connection and the connector already has <em>maxConnections</em> connections with peers
		 * established. Note that a connection is no longer considered stale, once data is being exchanged
		 * over it before it got evicted.
		 * 
		 * @param threshold The number of seconds.
		 * @return this builder for command chaining.
		 * @throws IllegalArgumentException if the given threshold is &lt; 1.
		 * @see #setMaxConnections(int)
		 */
		public Builder setStaleConnectionThreshold(final long threshold) {
			if (threshold < 1) {
				throw new IllegalArgumentException("Threshold must be at least 1 second");
			} else {
				config.staleConnectionThreshold = threshold;
				return this;
			}
		}

		/**
		 * Set the number of thread which should be used to handle DTLS
		 * connection.
		 * <p>
		 * The default value is 6 * <em>#(CPU cores)</em>.
		 * 
		 * @param threadCount the number of threads.
		 * @return this builder for command chaining.
		 */
		public Builder setConnectionThreadCount(int threadCount) {
			config.connectionThreadCount = threadCount;
			return this;
		}

		/**
		 * Set the number of thread which should be used to receive
		 * datagrams from the socket.
		 * <p>
		 * The default value is half of <em>#(CPU cores)</em>.
		 * 
		 * @param threadCount the number of threads.
		 * @return this builder for command chaining.
		 */
		public Builder setReceiverThreadCount(int threadCount) {
			config.receiverThreadCount = threadCount;
			return this;
		}

		/**
		 * Set the timeout of automatic session resumption in milliseconds.
		 * <p>
		 * The default value is {@code null}, no automatic session resumption.
		 * 
		 * @param timeoutInMillis the number of milliseconds.
		 * @return this builder for command chaining.
		 */
		public Builder setAutoResumptionTimeoutMillis(long timeoutInMillis) {
			config.autoResumptionTimeoutMillis = timeoutInMillis;
			return this;
		}

		/**
		 * Sets whether the connector should support the use of the TLS
		 * <a href="https://tools.ietf.org/html/rfc6066#section-3">
		 * Server Name Indication extension</a> in the DTLS handshake.
		 * <p>
		 * The default value of this property is {@code null}. If this property
		 * is not set explicitly, then the {@link Builder#build()} method
		 * will set it to {@code true}.
		 * 
		 * @param flag {@code true} if SNI should be used.
		 * @return this builder for command chaining.
		 */
		public Builder setSniEnabled(boolean flag) {
			config.sniEnabled = flag;
			return this;
		}

		/**
		 * Sets whether a HELLO_VERIFY_REQUEST should be used also for session
		 * resumption. If a CLIENT_HELLO with an session ID is used for session
		 * resumption, that session ID could be used to check, if this is a
		 * valid CLIENT_HELLO request. Though HELLO_VERIFY_REQUEST requires one
		 * message exchange more, it slows down a bit the handshake. If your
		 * system is expect to be attacked by spoofed IP message with valid
		 * session IDs, enable the use of verify requests as protection against
		 * that. The default is disabled (assuming that spoof attack with valid
		 * session IDs are negligible).
		 * 
		 * @param flag {@code true} if a HELLO_VERIFY_REQUEST should be used
		 *            also for session resumption
		 * @return this builder for command chaining.
		 */
		public Builder setVerifyRequestOnResumptionEnabled(boolean flag) {
			config.verifyRequestOnResumptionEnabled = flag;
			return this;
		}

		private boolean isConfiguredWithKeyPair() {
			return config.privateKey != null && config.publicKey != null;
		}

		/**
		 * Returns a potentially incomplete configuration. Only fields set by
		 * users are affected, there is no default value, no consistency check.
		 * To get a full usable {@link DtlsConnectorConfig} use {@link #build()}
		 * instead.
		 * 
		 * @return the incomplete Configuration
		 */
		public DtlsConnectorConfig getIncompleteConfig() {
			return config;
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
			// set default values
			if (config.address == null) {
				config.address = new InetSocketAddress(0);
			}
			if (config.enableReuseAddress == null) {
				config.enableReuseAddress = false;
			}
			if (config.earlyStopRetransmission == null) {
				config.earlyStopRetransmission = true;
			}
			if (config.retransmissionTimeout == null) {
				config.retransmissionTimeout = 1000;
			}
			if (config.maxRetransmissions == null) {
				config.maxRetransmissions = 4;
			}
			if (config.clientAuthenticationRequired == null) {
				config.clientAuthenticationRequired = true;
			}
			if (config.sendRawKey == null) {
				config.sendRawKey = true;
			}
			if (config.outboundMessageBufferSize == null) {
				config.outboundMessageBufferSize = 100000;
			}
			if (config.maxDeferredProcessedApplicationDataMessages == null){
				config.maxDeferredProcessedApplicationDataMessages = DEFAULT_MAX_DEFERRED_PROCESSED_APPLICATION_DATA_MESSAGES;
			}
			if (config.maxConnections == null){
				config.maxConnections = DEFAULT_MAX_CONNECTIONS;
			}
			if (config.connectionThreadCount == null) {
				config.connectionThreadCount = DEFAULT_EXECUTOR_THREAD_POOL_SIZE;
			}
			if (config.receiverThreadCount == null) {
				config.receiverThreadCount = DEFAULT_RECEIVER_THREADS;
			}
			if (config.staleConnectionThreshold == null) {
				config.staleConnectionThreshold = DEFAULT_STALE_CONNECTION_TRESHOLD;
			}
			if (config.certificateVerifier == null && config.trustStore != null) {
				config.certificateVerifier = new StaticCertificateVerifier(config.trustStore);
			}
			if (config.supportedCipherSuites == null || config.supportedCipherSuites.length == 0) {
				determineCipherSuitesFromConfig();
			}
			if (config.trustedRPKs == null) {
				// must be set after determineCipherSuitesFromConfig(),
				// otherwise this would be interpreted for client only
				// as ECDHE_ECDSA support!
				config.trustedRPKs = new TrustAllRpks();
			}
			if (config.sniEnabled == null) {
				config.sniEnabled = Boolean.TRUE;
			}
			if (config.verifyRequestOnResumptionEnabled == null) {
				config.verifyRequestOnResumptionEnabled = Boolean.FALSE;
			}

			// check cipher consistency
			if (config.supportedCipherSuites == null || config.supportedCipherSuites.length == 0) {
				throw new IllegalStateException("Supported cipher suites must be set either " +
						"explicitly or implicitly by means of setting the identity or PSK store");
			}
			for (CipherSuite suite : config.supportedCipherSuites) {
				switch (suite) {
				case TLS_PSK_WITH_AES_128_CCM_8:
				case TLS_PSK_WITH_AES_128_CBC_SHA256:
				case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
					verifyPskBasedCipherConfig();
					break;
				case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
				case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
					verifyEcBasedCipherConfig();
					break;
				default:
					break;
				}
			}

			return config;
		}

		private void verifyPskBasedCipherConfig() {
			if (config.pskStore == null) {
				throw new IllegalStateException("PSK store must be set when support for " +
						CipherSuite.TLS_PSK_WITH_AES_128_CCM_8.name() + " is configured");
			}
		}

		private void verifyEcBasedCipherConfig() {
			if (!clientOnly) {
				if (config.getPrivateKey() == null || config.getPublicKey() == null) {
					throw new IllegalStateException("Identity must be set");
				} else if ( !EC_ALGORITHM_NAME.equals(config.privateKey.getAlgorithm()) ||
						!EC_ALGORITHM_NAME.equals(config.getPublicKey().getAlgorithm()) ) {
					// test if private & public key are ECDSA capable
					throw new IllegalStateException("Keys must be ECDSA capable when support for an " +
							"ECDHE_ECDSA based cipher suite is configured");
				}
			}
		}

		private void determineCipherSuitesFromConfig() {
			// user has not explicitly set cipher suites
			// try to guess his intentions from properties he has set
			List<CipherSuite> ciphers = new ArrayList<>();
			boolean certificates = isConfiguredWithKeyPair();
			if (!certificates && clientOnly) {
				certificates = config.trustedRPKs != null || (config.certificateVerifier != null);
			}

			if (certificates) {
				ciphers.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
				ciphers.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
			}

			if (config.pskStore != null) {
				ciphers.add(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8);
				ciphers.add(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256);
				ciphers.add(CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256);
			}

			config.supportedCipherSuites = ciphers.toArray(new CipherSuite[0]);
		}
	}
}
