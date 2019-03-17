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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add server only.
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

import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.ConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.SessionCache;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.dtls.rpkstore.TrustAllRpks;
import org.eclipse.californium.scandium.dtls.rpkstore.TrustedRpkStore;
import org.eclipse.californium.scandium.dtls.x509.CertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.StaticCertificateVerifier;
import org.eclipse.californium.scandium.util.ListUtils;

/**
 * A container for all configuration options of a <code>DTLSConnector</code>.
 * <p>
 * Instances of this class are immutable and can only be created by means of
 * the {@link Builder}, e.g.
 * </p>
 * <pre>
 * InetSocketAddress bindToAddress = new InetSocketAddress("localhost", 0); // use ephemeral port
 * DtlsConnectorConfig config = new DtlsConnectorConfig.Builder()
 *    .setAddress(bindToAddress)
 *    .setPskStore(new StaticPskStore("identity", "secret".getBytes()))
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
	 * The default value for the <em>maxFragmentedHandshakeMessageLength</em> property.
	 */
	public static final int DEFAULT_MAX_FRAGMENTED_HANDSHAKE_MESSAGE_LENGTH = 8192;
	/**
	 * The default value for the <em>staleConnectionThreshold</em> property.
	 */
	public static final long DEFAULT_STALE_CONNECTION_TRESHOLD = 30 * 60; // 30 minutes
	/**
	 * The default value for the <em>retransmissionTimeout</em> property.
	 */
	public static final int DEFAULT_RETRANSMISSION_TIMEOUT_MS = 1000;
	/**
	 * The default value for the <em>maxRetransmissions</em> property.
	 */
	public static final int DEFAULT_MAX_RETRANSMISSIONS = 4;
	/**
	 * The default value for the <em>verifyPeersOnResumptionThreshold</em>
	 * property.
	 */
	public static final int DEFAULT_VERIFY_PEERS_ON_RESUMPTION_THRESHOLD_IN_PERCENT = 30;
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

	/**
	 * Local network interface.
	 */
	private InetSocketAddress address;
	/**
	 * Truststore for trusted certificates  
	 */
	private X509Certificate[] trustStore;
	/**
	 * Certificate verifier for dynamic trust.
	 */
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

	/**
	 * The maximum length of a reassembled fragmented handshake message.
	 */
	private Integer maxFragmentedHandshakeMessageLength;

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

	/** does the server want/request the client to authenticate */
	private Boolean clientAuthenticationWanted;

	/** does the server require the client to authenticate */
	private Boolean clientAuthenticationRequired;

	/** does not start handshakes */
	private Boolean serverOnly;

	/** certificate types to be used to identify this peer */
	private List<CertificateType> identityCertificateTypes;

	/** certificate types to be used to trust the other peer */
	private List<CertificateType> trustCertificateTypes;

	/** store of the PSK */
	private PskStore pskStore;

	/** the private key for RPK and X509 mode, right now only EC type is supported */
	private PrivateKey privateKey;

	/** the public key for RPK and X.509 mode, right now only EC type is supported */
	private PublicKey publicKey;

	/** the certificate for X509 mode */
	private List<X509Certificate> certChain;

	/** the supported cipher suites in order of preference */
	private List<CipherSuite> supportedCipherSuites;

	/** the trust store for RPKs **/
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

	/**
	 * Indicates, that "server name indication" is used (client side) and
	 * supported (server side). The support on the server side currently
	 * includes a server name specific PSK secret lookup and to forward the
	 * server name to the CoAP stack in the {@link org.eclipse.californium.elements.EndpointContext}.
	 * 
	 * See <a href="https://tools.ietf.org/html/rfc6066#section-3">RFC 6066, Section 3</a>
	 */
	private Boolean sniEnabled;

	/**
	 * Threshold of pending handshakes without verified peer for session
	 * resumption in percent of {link {@link #maxConnections}. If more such
	 * handshakes are pending, then use a verify request to ensure, that the
	 * used client hello is not spoofed.
	 * 
	 * <pre>
	 * 0 := always use a HELLO_VERIFY_REQUEST
	 * 1 ... 100 := dynamically determine to use a HELLO_VERIFY_REQUEST.
	 * </pre>
	 * 
	 * Default {@link #DEFAULT_VERIFY_PEERS_ON_RESUMPTION_THRESHOLD_IN_PERCENT}.
	 * 
	 * @see #getVerifyPeersOnResumptionThreshold()
	 */
	private Integer verifyPeersOnResumptionThreshold;

	/**
	 * Indicates, that no session id is used by this server. The sessions are not
	 * cached by this server and can not be resumed.
	 */
	private Boolean useNoServerSessionId;

	/**
	 * Use anti replay filter.
	 * 
	 * @see http://tools.ietf.org/html/rfc6347#section-4.1
	 */
	private Boolean useAntiReplayFilter;

	/**
	 * Use filter for record in window only.
	 * 
	 * Messages too old for the filter window will pass the filter.
	 * 
	 * @see http://tools.ietf.org/html/rfc6347#section-4.1
	 */
	private Boolean useWindowFilter;

	/**
	 * Logging tag.
	 * 
	 * Tag logging messages, if multiple connectors share the same logging
	 * instance.
	 */
	private String loggingTag;

	/**
	 * Connection id generator. {@code null}, if connection id is not supported.
	 * The generator may only support the use of a connection id without using
	 * it by itself. In that case
	 * {@link ConnectionIdGenerator#useConnectionId()} will return
	 * {@code false}.
	 */
	private ConnectionIdGenerator connectionIdGenerator;

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
	 * Gets the maximum length of a reassembled fragmented handshake message.
	 * 
	 * @return maximum length
	 */
	public Integer getMaxFragmentedHandshakeMessageLength() {
		return maxFragmentedHandshakeMessageLength;
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
	 * <a href="https://tools.ietf.org/html/rfc6066#section-3"> Server Name
	 * Indication extension</a> in the DTLS handshake.
	 * <p>
	 * If enabled, the client side should send a server name extension, if the
	 * server is specified with hostname rather then with a raw ip-address. The
	 * server side support currently includes a server name specific PSK secret
	 * lookup and a forwarding of the server name to the CoAP stack in the
	 * {@link DtlsEndpointContext}. The x509 or RPK credentials lookup is currently
	 * not server name specific, therefore the server's certificate will be the
	 * same, regardless of the indicated server name.
	 * <p>
	 * The default value of this property is {@code null}. If this property is
	 * not set explicitly using {@link Builder#setSniEnabled(boolean)}, then the
	 * {@link Builder#build()} method will set it to {@code false}.
	 * 
	 * @return {@code true} if SNI should be used.
	 */
	public Boolean isSniEnabled() {
		return sniEnabled;
	}

	/**
	 * Threshold to use a HELLO_VERIFY_REQUEST also for session resumption in
	 * percent of {@link #getMaxConnections()}. Though a CLIENT_HELLO with an
	 * session id is used in session resumption, that session ID could be used
	 * to check.
	 * 
	 * <pre>
	 * Value 
	 * 0 : always use a verify request.
	 * 1 ... 100 : dynamically use a verify request.
	 * </pre>
	 * 
	 * Peers are identified by their endpoint (ip-address and port) and dtls
	 * sessions have a id and may be also related to an endpoint. If a peer
	 * resumes its own session (by id, and that session is related to the same
	 * endpoint as the peer), no verify request is used. If a peer resumes as
	 * session (by id), but a different session is related to its endpoint, then
	 * a verify request is used to ensure, that the peer really owns that
	 * endpoint. If a peer resumes a session, and the endpoint of the peer is
	 * either unused or not related to a established session, this threshold
	 * controls, if a verify request is sued or not. If more resumption
	 * handshakes without verified peers are pending than this threshold, then a
	 * verify request is used.
	 * 
	 * Note: a value larger than 0 will call
	 * {@link SessionCache#get(org.eclipse.californium.scandium.dtls.SessionId)}.
	 * If that implementation is expensive, please ensure, that this value is
	 * configured with {@code 0}. Otherwise, CLIENT_HELLOs with invalid session
	 * ids may be spoofed and gets too expensive.
	 * 
	 * @return threshold handshakes without verified peer in percent of
	 *         {@link #getMaxConnections()}.
	 */
	public Integer getVerifyPeersOnResumptionThreshold() {
		return verifyPeersOnResumptionThreshold;
	}

	/**
	 * Gets connection ID generator.
	 * 
	 * @return connection id generator. {@code null} for not supported. The
	 *         returned generator may only support the use of a connection id
	 *         without using it by itself. In that case
	 *         {@link ConnectionIdGenerator#useConnectionId()} will return
	 *         {@code false}.
	 */
	public ConnectionIdGenerator getConnectionIdGenerator() {
		return connectionIdGenerator;
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
	public List<X509Certificate> getCertificateChain() {
		return certChain;
	}

	/**
	 * Gets the cipher suites the connector should advertise in a DTLS
	 * handshake.
	 * 
	 * @return the supported cipher suites (ordered by preference)
	 */
	public List<CipherSuite> getSupportedCipherSuites() {
		return supportedCipherSuites;
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
	 * Gets the trusted root certificates to use when verifying a peer's
	 * certificate during authentication.
	 * 
	 * Only valid, if {@link Builder#setTrustStore(Certificate[])} is used.
	 * 
	 * @return the root certificates. If empty (length of zero), all
	 *         certificates are trusted. If {@code null}, the trust may be
	 *         implemented by a {@link CertificateVerifier}.
	 * @see #getCertificateVerifier()
	 */
	public X509Certificate[] getTrustStore() {
		if (trustStore == null) {
			return null;
		} else {
			return Arrays.copyOf(trustStore, trustStore.length);
		}
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
	 * Gets whether the connector wants (requests) DTLS clients to authenticate
	 * during the handshake. The handshake doesn't fail, if the client didn't
	 * authenticate itself during the handshake. That mostly requires the client
	 * to use a proprietary mechanism to authenticate itself on the application
	 * layer (e.g. username/password). It's mainly used, if the implementation
	 * of the other peer has no PSK cipher suite and client certificate should
	 * not be used for some reason.
	 * 
	 * Only used by the DTLS server side.
	 * 
	 * @return <code>true</code> if clients wanted to authenticate
	 */
	public Boolean isClientAuthenticationWanted() {
		return clientAuthenticationWanted;
	}

	/**
	 * Gets whether the connector requires DTLS clients to authenticate during
	 * the handshake. Only used by the DTLS server side.
	 * 
	 * @return <code>true</code> if clients need to authenticate
	 */
	public Boolean isClientAuthenticationRequired() {
		return clientAuthenticationRequired;
	}

	/**
	 * Gets whether the connector acts only as server and doesn't start new handshakes.
	 * 
	 * @return <code>true</code> if the connector acts only as server
	 */
	public Boolean isServerOnly() {
		return serverOnly;
	}

	/**
	 * Gets the certificate types for the identity of this peer.
	 * 
	 * In the order of preference.
	 * 
	 * @return certificate types ordered by preference, or {@code null}, if no
	 *         certificates are used to identify this peer.
	 */
	public List<CertificateType> getIdentityCertificateTypes() {
		return identityCertificateTypes;
	}

	/**
	 * Gets the certificate types for the trust of the other peer.
	 * 
	 * In the order of preference.
	 * 
	 * @return certificate types ordered by preference, or {@code null}, if no
	 *         certificates are used to trust the other peer.
	 */
	public List<CertificateType> getTrustCertificateTypes() {
		return trustCertificateTypes;
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
	 * traffic is routed over a NAT. The value may be overridden by the endpoint
	 * context attribute {@link DtlsEndpointContext#KEY_RESUMPTION_TIMEOUT}.
	 * 
	 * @return timeout in milliseconds, or {@code null}, if no automatic
	 *         resumption is intended.
	 */
	public Long getAutoResumptionTimeoutMillis() {
		return autoResumptionTimeoutMillis;
	}

	/**
	 * Indicates, that no session id is used by this server and so session are
	 * also not cached by this server and can not be resumed.
	 * 
	 * @return {@code true} if no session id is used by this server.
	 */
	public Boolean useNoServerSessionId() {
		return useNoServerSessionId;
	}

	/**
	 * Use anti replay filter.
	 * 
	 * @return {@code true}, apply anti replay filter
	 * @see http://tools.ietf.org/html/rfc6347#section-4.1
	 */
	public Boolean useAntiReplayFilter() {
		return useAntiReplayFilter;
	}

	/**
	 * Use window filter.
	 * 
	 * Messages too old for the filter window will pass the filter.
	 * 
	 * @return {@code true}, apply window filter
	 * @see http://tools.ietf.org/html/rfc6347#section-4.1
	 */
	public Boolean useWindowFilter() {
		return useWindowFilter;
	}

	/**
	 * @return The trust store for raw public keys verified out-of-band for
	 *         DTLS-RPK handshakes
	 */
	public TrustedRpkStore getRpkTrustStore() {
		return trustedRPKs;
	}

	/**
	 * Get instance logging tag.
	 * 
	 * @return logging tag.
	 */
	public String getLoggingTag() {
		return loggingTag;
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
		cloned.maxFragmentedHandshakeMessageLength = maxFragmentedHandshakeMessageLength;
		cloned.retransmissionTimeout = retransmissionTimeout;
		cloned.maxRetransmissions = maxRetransmissions;
		cloned.maxTransmissionUnit = maxTransmissionUnit;
		cloned.clientAuthenticationRequired = clientAuthenticationRequired;
		cloned.clientAuthenticationWanted = clientAuthenticationWanted;
		cloned.serverOnly = serverOnly;
		cloned.identityCertificateTypes = identityCertificateTypes;
		cloned.trustCertificateTypes = trustCertificateTypes;
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
		cloned.receiverThreadCount = receiverThreadCount;
		cloned.autoResumptionTimeoutMillis = autoResumptionTimeoutMillis;
		cloned.sniEnabled = sniEnabled;
		cloned.verifyPeersOnResumptionThreshold = verifyPeersOnResumptionThreshold;
		cloned.useNoServerSessionId = useNoServerSessionId;
		cloned.loggingTag = loggingTag;
		cloned.useAntiReplayFilter = useAntiReplayFilter;
		cloned.useWindowFilter = useWindowFilter;
		cloned.connectionIdGenerator = connectionIdGenerator;
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
		private boolean extendedCipherSuites;

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
		 * Create a builder from an existing DtlsConnectorConfig. This allow to
		 * create a new configuration starting from values of another one.
		 * 
		 * @param initialConfiguration initial configuration
		 */
		public Builder(DtlsConnectorConfig initialConfiguration) {
			config = (DtlsConnectorConfig) initialConfiguration.clone();
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
		 * Set usage of extended cipher suites for default cipher suites, if
		 * {@link #setSupportedCipherSuites} is not called.
		 * 
		 * @param extendedCipherSuites {@code true} use extended cipher suites
		 *            as default
		 * @return this builder for command chaining
		 */
		public Builder setExtendedCipherSuites(boolean extendedCipherSuites) {
			if (config.supportedCipherSuites != null) {
				throw new IllegalArgumentException("cipher-suites are already provided!");
			}
			this.extendedCipherSuites = extendedCipherSuites;
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
			if (config.clientAuthenticationRequired != null || config.clientAuthenticationWanted != null) {
				throw new IllegalStateException("client only is not support with server side client authentication!");
			} else if (config.serverOnly != null) {
				throw new IllegalStateException("client only is not support with server only!");
			} else if (config.useNoServerSessionId != null && config.useNoServerSessionId.booleanValue()) {
				throw new IllegalStateException("client only is not support with no server session id!");
			}
			clientOnly = true;
			return this;
		}

		/**
		 * Indicates that the <em>DTLSConnector</em> will only act as server.
		 * 
		 * A server only accepts handshakes, it never starts them.
		 * 
		 * @param enable {@code true} if the connector acts only as server.
		 * @return this builder for command chaining
		 */
		public Builder setServerOnly(boolean enable) {
			if (clientOnly) {
				throw new IllegalStateException("server only is not supported for client only!");
			}
			config.serverOnly = enable;
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
		 * Set maximum length of handshake message.
		 * 
		 * @param length maximum length of handshake message
		 * @return this builder for command chaining
		 */
		public Builder setMaxFragmentedHandshakeMessageLength(Integer length) {
			config.maxFragmentedHandshakeMessageLength = length;
			return this;
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
		 * Sets whether the connector wants (requests) DTLS clients to
		 * authenticate during the handshake. The handshake doesn't fail, if the
		 * client didn't authenticate itself during the handshake. That mostly
		 * requires the client to use a proprietary mechanism to authenticate
		 * itself on the application layer (e.g. username/password). It's mainly
		 * used, if the implementation of the other peer has no PSK cipher suite
		 * and client certificate should not be used for some reason.
		 * 
		 * The default is {@code false}. Only used by the DTLS server side.
		 * 
		 * @param authWanted <code>true</code> if clients wanted to authenticate
		 * @return this builder for command chaining
		 * @throws IllegalStateException if configuration is for client only
		 * @throws IllegalArgumentException if authWanted is {@code true}, but
		 *             {@link #setClientAuthenticationRequired(boolean)} was set
		 *             to {@code true} before.
		 */
		public Builder setClientAuthenticationWanted(boolean authWanted) {
			if (clientOnly) {
				throw new IllegalStateException("client authentication is not supported for client only!");
			}
			if (authWanted && Boolean.TRUE.equals(config.clientAuthenticationRequired)) {
				throw new IllegalArgumentException("client authentication is already required!");
			}
			config.clientAuthenticationWanted = authWanted;
			return this;
		}

		/**
		 * Sets whether the connector requires DTLS clients to authenticate
		 * during the handshake.
		 * 
		 * The default is {@code true}. If
		 * {@link #setClientAuthenticationWanted(boolean)} is set to
		 * {@code true}, the default is {@code false}. Only used by the DTLS
		 * server side.
		 * 
		 * @param authRequired <code>true</code> if clients need to authenticate
		 * @return this builder for command chaining
		 * @throws IllegalStateException if configuration is for client only
		 * @throws IllegalArgumentException if authWanted is {@code true}, but
		 *             {@link #setClientAuthenticationWanted(boolean)} was set
		 *             to {@code true} before.
		 */
		public Builder setClientAuthenticationRequired(boolean authRequired) {
			if (clientOnly) {
				throw new IllegalStateException("client authentication is not supported for client only!");
			}
			if (authRequired && Boolean.TRUE.equals(config.clientAuthenticationWanted)) {
				throw new IllegalArgumentException("client authentication is already wanted!");
			}
			config.clientAuthenticationRequired = authRequired;
			return this;
		}

		/**
		 * Sets the cipher suites supported by the connector.
		 * <p>
		 * The connector will use these cipher suites (in exactly the same
		 * order) during the DTLS handshake when negotiating a cipher suite with
		 * a peer.
		 * 
		 * @param cipherSuites the supported cipher suites in the order of preference
		 * @return this builder for command chaining
		 * @throws NullPointerException if the given array is <code>null</code>
		 * @throws IllegalArgumentException if the given array is empty or
		 *             contains {@link CipherSuite#TLS_NULL_WITH_NULL_NULL}
		 */
		public Builder setSupportedCipherSuites(CipherSuite... cipherSuites) {
			if (cipherSuites == null) {
				throw new NullPointerException("Connector must support at least one cipher suite");
			}
			return setSupportedCipherSuites(Arrays.asList(cipherSuites));
		}

		/**
		 * Sets the cipher suites supported by the connector.
		 * <p>
		 * The connector will use these cipher suites (in exactly the same
		 * order) during the DTLS handshake when negotiating a cipher suite with
		 * a peer.
		 * 
		 * @param cipherSuites the supported cipher suites in the order of
		 *            preference
		 * @return this builder for command chaining
		 * @throws NullPointerException if the given array is <code>null</code>
		 * @throws IllegalArgumentException if the given array is empty or
		 *             contains {@link CipherSuite#TLS_NULL_WITH_NULL_NULL}, or
		 *             contains a cipher suite, not supported by the JVM.
		 */
		public Builder setSupportedCipherSuites(List<CipherSuite> cipherSuites) {
			if (cipherSuites == null) {
				throw new NullPointerException("Connector must support at least one cipher suite");
			}
			if (cipherSuites.isEmpty()) {
				throw new IllegalArgumentException("Connector must support at least one cipher suite");
			} 
			if (cipherSuites.contains(CipherSuite.TLS_NULL_WITH_NULL_NULL)) {
				throw new IllegalArgumentException("NULL Cipher Suite is not supported by connector");
			}
			if (extendedCipherSuites) {
				throw new IllegalArgumentException("Extended default cipher-suites are already provided!");
			}
			for (CipherSuite cipherSuite : cipherSuites) {
				if (!cipherSuite.isSupported()) {
					throw new IllegalArgumentException("cipher-suites " + cipherSuite + " is not supported by JVM!");
				}
			}
			config.supportedCipherSuites = cipherSuites;
			return this;
		}

		/**
		 * Sets the cipher suites supported by the connector.
		 * <p>
		 * The connector will use these cipher suites (in exactly the same
		 * order) during the DTLS handshake when negotiating a cipher suite with
		 * a peer.
		 * 
		 * @param cipherSuites the names of supported cipher suites in the order
		 *            of preference (see <a href=
		 *            "http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4">
		 *            IANA registry</a> for a list of cipher suite names)
		 * @return this builder for command chaining
		 * @throws NullPointerException if the given array is <code>null</code>
		 * @throws IllegalArgumentException if the given array is empty or
		 *             contains <em>TLS_NULL_WITH_NULL_NULL</em> or if a name
		 *             from the given list is unsupported (yet)
		 */
		public Builder setSupportedCipherSuites(String... cipherSuites) {
			if (cipherSuites == null) {
				throw new NullPointerException("Connector must support at least one cipher suite");
			}
			List<CipherSuite> suites = new ArrayList<>(cipherSuites.length);
			for (int i = 0; i < cipherSuites.length; i++) {
				CipherSuite knownSuite = CipherSuite.getTypeByName(cipherSuites[i]);
				if (knownSuite != null) {
					suites.add(knownSuite);
				} else {
					throw new IllegalArgumentException(
							String.format("Cipher suite [%s] is not (yet) supported", cipherSuites[i]));
				}
			}
			return setSupportedCipherSuites(suites);
		}

		/**
		 * Activate/Deactivate experimental feature: Stop retransmission at
		 * first received handshake message.
		 * 
		 * @param activate Set it to true if retransmissions should be stopped
		 *            as soon as we receive a handshake message
		 * @return this builder for command chaining
		 */
		public Builder setEarlyStopRetransmission(boolean activate) {
			config.earlyStopRetransmission = activate;
			return this;
		}

		/**
		 * Sets the (starting) time to wait before a handshake package gets re-transmitted.
		 * 
		 * On each retransmission, the time is doubled.
		 * 
		 * @param timeout the time in milliseconds
		 * @return this builder for command chaining
		 * @throws IllegalArgumentException if the given timeout is negative
		 */
		public Builder setRetransmissionTimeout(int timeout) {
			if (timeout < 0) {
				throw new IllegalArgumentException("Retransmission timeout must not be negative");
			}
			config.retransmissionTimeout = timeout;
			return this;
		}

		/**
		 * Sets the key store to use for authenticating clients based on a
		 * pre-shared key.
		 * 
		 * If used together with {@link #setIdentity(PrivateKey, PublicKey)} or
		 * {@link #setIdentity(PrivateKey, Certificate[], CertificateType...)}
		 * the default preference uses the certificate based cipher suites. To
		 * change that, use {@link #setSupportedCipherSuites(CipherSuite...)} or
		 * {@link #setSupportedCipherSuites(String...)}.
		 * 
		 * @param pskStore the key store
		 * @return this builder for command chaining
		 */
		public Builder setPskStore(PskStore pskStore) {
			config.pskStore = pskStore;
			return this;
		}

		/**
		 * Sets the connector's identifying properties by means of a private and
		 * public key pair.
		 * <p>
		 * Using this method implies that the connector <em>only</em> supports
		 * <em>RawPublicKey</em> mode for authenticating to a peer. This sets
		 * the {@link DtlsConnectorConfig#identityCertificateTypes} to
		 * RAW_PUBLIC_KEY also. Please ensure, that you setup
		 * {@link #setRpkTrustStore(TrustedRpkStore)}, or [@link
		 * {@link #setRpkTrustAll()}}, if you want to trust the other peer using
		 * RAW_PUBLIC_KEY also.
		 * 
		 * If X_509 is intended to be supported together with RAW_PUBLIC_KEY,
		 * please use
		 * {@link #setIdentity(PrivateKey, Certificate[], CertificateType...)}
		 * instead and provide RAW_PUBLIC_KEY together with X_509 in the wanted
		 * preference order.
		 *
		 * If used together with {@link #setPskStore(PskStore)}, the default
		 * preference uses this certificate based cipher suites. To change that,
		 * use {@link #setSupportedCipherSuites(CipherSuite...)} or
		 * {@link #setSupportedCipherSuites(String...)}.
		 * 
		 * @param privateKey the private key used for creating signatures
		 * @param publicKey the public key a peer can use to verify possession
		 *            of the private key
		 * @return this builder for command chaining
		 * @throws NullPointerException if any of the given keys is
		 *             <code>null</code>
		 * @see #setRpkTrustAll()
		 * @see #setRpkTrustStore(TrustedRpkStore)
		 */
		public Builder setIdentity(PrivateKey privateKey, PublicKey publicKey) {
			if (privateKey == null) {
				throw new NullPointerException("The private key must not be null");
			}
			if (publicKey == null) {
				throw new NullPointerException("The public key must not be null");
			}
			config.privateKey = privateKey;
			config.publicKey = publicKey;
			config.certChain = null;
			config.identityCertificateTypes = new ArrayList<>(1);
			config.identityCertificateTypes.add(CertificateType.RAW_PUBLIC_KEY);
			return this;
		}

		/**
		 * Sets the connector's identifying properties by means of a private key
		 * and a corresponding issuer certificates chain.
		 * <p>
		 * In server mode the key and certificates are used to prove the
		 * server's identity to the client. In client mode the key and
		 * certificates are used to prove the client's identity to the server.
		 * Please ensure, that you setup either
		 * {@link #setCertificateVerifier(CertificateVerifier)},
		 * {@link #setTrustStore(Certificate[])}, {@link #setRpkTrustAll()},
		 * {@link #setRpkTrustStore(TrustedRpkStore)}, if you want to trust the
		 * other peer also using certificates.
		 * 
		 * If used together with {@link #setPskStore(PskStore)}, the default
		 * preference uses this certificate based cipher suites. To change that,
		 * use {@link #setSupportedCipherSuites(CipherSuite...)} or
		 * {@link #setSupportedCipherSuites(String...)}.
		 * 
		 * @param privateKey the private key used for creating signatures
		 * @param certificateChain the chain of X.509 certificates asserting the
		 *            private key subject's identity
		 * @param certificateTypes list of certificate types in the order of
		 *            preference. Default is X_509. To support RAW_PUBLIC_KEY
		 *            also, use X_509 and RAW_PUBLIC_KEY in the order of the
		 *            preference. If only RAW_PUBLIC_KEY is used, the
		 *            certificate chain will set to {@code null}.
		 * @return this builder for command chaining
		 * @throws NullPointerException if the given private key or certificate
		 *             chain is <code>null</code>
		 * @throws IllegalArgumentException if the certificate chain does not
		 *             contain any certificates, or contains a non-X.509
		 *             certificate
		 * @see #setTrustStore(Certificate[])
		 * @see #setCertificateVerifier(CertificateVerifier)
		 * @see #setRpkTrustAll()
		 * @see #setRpkTrustStore(TrustedRpkStore)
		 */
		public Builder setIdentity(PrivateKey privateKey, Certificate[] certificateChain,
				CertificateType... certificateTypes) {
			if (certificateTypes == null || certificateTypes.length == 0) {
				return setIdentity(privateKey, certificateChain, (List<CertificateType>) null);
			} else {
				return setIdentity(privateKey, certificateChain, Arrays.asList(certificateTypes));
			}
		}

		/**
		 * Sets the connector's identifying properties by means of a private key
		 * and a corresponding issuer certificates chain.
		 * <p>
		 * In server mode the key and certificates are used to prove the
		 * server's identity to the client. In client mode the key and
		 * certificates are used to prove the client's identity to the server.
		 * Please ensure, that you setup either
		 * {@link #setCertificateVerifier(CertificateVerifier)},
		 * {@link #setTrustStore(Certificate[])}, {@link #setRpkTrustAll()},
		 * {@link #setRpkTrustStore(TrustedRpkStore)}, if you want to trust the
		 * other peer also using certificates.
		 * 
		 * If used together with {@link #setPskStore(PskStore)}, the default
		 * preference uses this certificate based cipher suites. To change that,
		 * use {@link #setSupportedCipherSuites(CipherSuite...)} or
		 * {@link #setSupportedCipherSuites(String...)}.
		 * 
		 * @param privateKey the private key used for creating signatures
		 * @param certificateChain the chain of X.509 certificates asserting the
		 *            private key subject's identity
		 * @param certificateTypes list of certificate types in the order of
		 *            preference. Default is X_509. To support RAW_PUBLIC_KEY
		 *            also, use X_509 and RAW_PUBLIC_KEY in the order of the
		 *            preference. If only RAW_PUBLIC_KEY is used, the
		 *            certificate chain will set to {@code null}.
		 * @return this builder for command chaining
		 * @throws NullPointerException if the given private key or certificate
		 *             chain is <code>null</code>
		 * @throws IllegalArgumentException if the certificate chain does not
		 *             contain any certificates, or contains a non-X.509
		 *             certificate. Or the provide certificateTypes is empty.
		 * @see #setTrustStore(Certificate[])
		 * @see #setCertificateVerifier(CertificateVerifier)
		 * @see #setRpkTrustAll()
		 * @see #setRpkTrustStore(TrustedRpkStore)
		 */
		public Builder setIdentity(PrivateKey privateKey, Certificate[] certificateChain,
				List<CertificateType> certificateTypes) {
			if (privateKey == null) {
				throw new NullPointerException("The private key must not be null!");
			} else if (certificateChain == null) {
				throw new NullPointerException("The certificate chain must not be null!");
			} else if (certificateChain.length < 1) {
				throw new IllegalArgumentException("The certificate chain must not be empty!");
			} else if (certificateTypes != null && certificateTypes.isEmpty()) {
				throw new IllegalArgumentException("The certificate types must not be empty!");
			} else if (certificateTypes != null) {
				for (CertificateType certificateType : certificateTypes) {
					if (!certificateType.isSupported()) {
						throw new IllegalArgumentException(
								"The certificate type " + certificateType + " is not supported!");
					}
				}
			}
			config.privateKey = privateKey;
			config.certChain = Arrays.asList(SslContextUtil.asX509Certificates(certificateChain));
			config.publicKey = config.certChain.get(0).getPublicKey();
			if (certificateTypes == null) {
				config.identityCertificateTypes = new ArrayList<>(1);
				config.identityCertificateTypes.add(CertificateType.X_509);
			} else {
				config.identityCertificateTypes = certificateTypes;
				if (!config.identityCertificateTypes.contains(CertificateType.X_509)) {
					config.certChain = null;
				}
			}
			return this;
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
		 * This method must not be called, if
		 * {@link #setCertificateVerifier(CertificateVerifier)} is already set.
		 * 
		 * @param trustedCerts the trusted root certificates. If empty (length
		 *            of zero), trust all certificates.
		 * @return this builder for command chaining
		 * @throws NullPointerException if the given array is <code>null</code>
		 * @throws IllegalArgumentException if the array contains a non-X.509
		 *             certificate
		 * @throws IllegalStateException if
		 *             {@link #setCertificateVerifier(CertificateVerifier)} is
		 *             already set.
		 * @see #setTrustCertificateTypes
		 */
		public Builder setTrustStore(Certificate[] trustedCerts) {
			if (trustedCerts == null) {
				throw new NullPointerException("Trust store must not be null");
			} else if (trustedCerts.length == 0) {
				config.trustStore = new X509Certificate[0];
			} else if (config.certificateVerifier != null) {
				throw new IllegalStateException("Trust store must not be used after certificate verifier is set!");
			} else {
				config.trustStore = SslContextUtil.asX509Certificates(trustedCerts);
			}
			return this;
		}

		/**
		 * Sets the logic in charge of validating a X.509 certificate chain.
		 *
		 * Here are a few use cases where a custom implementation would be
		 * needed:
		 * <ul>
		 * <li>client certificate authentication based on a dynamic trusted CA
		 * <li>revocation not provided by the default implementation (e.g. OCSP)
		 * <li>cipher suites restriction per client
		 * </ul>
		 * 
		 * This method must not be called, if
		 * {@link #setTrustStore(Certificate[])} is already set.
		 *
		 * @param verifier certificate verifier
		 * @return this builder for command chaining
		 * @throws NullPointerException if the given certificate verifier is
		 *             {@code null}
		 * @throws IllegalStateException if
		 *             {@link #setTrustStore(Certificate[])} is already set.
		 * @see #setTrustCertificateTypes
		 */
		public Builder setCertificateVerifier(CertificateVerifier verifier) {
			if (verifier == null) {
				throw new NullPointerException("CertificateVerifier must not be null");
			} else if (config.trustStore != null) {
				throw new IllegalStateException("CertificateVerifier must not be used after trust store is set!");
			}
			config.certificateVerifier = verifier;
			return this;
		}

		/**
		 * Sets the store for trusted raw public keys.
		 * 
		 * @param store the raw public keys trust store
		 * 
		 * @return this builder for command chaining
		 * @throws NullPointerException if the given store is {@code null}
		 * @see #setTrustCertificateTypes
		 */
		public Builder setRpkTrustStore(TrustedRpkStore store) {
			if (store == null) {
				throw new IllegalStateException("Must provide a non-null rpk trust store");
			}
			config.trustedRPKs = store;
			return this;
		}

		/**
		 * Sets the store for trusted raw public key to trust all public keys.
		 * 
		 * @return this builder for command chaining
		 */
		public Builder setRpkTrustAll() {
			config.trustedRPKs = new TrustAllRpks();
			return this;
		}

		/**
		 * Sets the certificate types for the trust of the other peer.
		 * 
		 * In the order of preference.
		 * 
		 * If trusted certificates are provided with one of the setter below,
		 * the certificate type are adjusted in the order RAW_PUBLIC_KEY and
		 * X_509. This setter could be used to change that order. If a
		 * certificate type is included in this list, but the related trusted
		 * certificates are not provided, {@link #build()} will throw a
		 * {@link IllegalStateException}.
		 * 
		 * @param certificateTypes certificate types in order of preference
		 * @return this builder for command chaining
		 * @throws NullPointerException if the given certificate types is
		 *             {@code null}
		 * @throws IllegalArgumentException if the certificate types are empty
		 * @see #setRpkTrustAll()
		 * @see #setRpkTrustStore(TrustedRpkStore)
		 * @see #setCertificateVerifier(CertificateVerifier)
		 * @see #setTrustStore(Certificate[])
		 */
		public Builder setTrustCertificateTypes(CertificateType... certificateTypes) {
			if (certificateTypes == null) {
				throw new NullPointerException("CertificateTypes must not be null!");
			} else if (certificateTypes.length == 0) {
				throw new IllegalArgumentException("CertificateTypes must not be empty!");
			}
			for (CertificateType certificateType : certificateTypes) {
				if (!certificateType.isSupported()) {
					throw new IllegalArgumentException(
							"The certificate type " + certificateType + " is not supported!");
				}
			}
			config.trustCertificateTypes = Arrays.asList(certificateTypes);
			return this;
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
			}
			config.maxDeferredProcessedApplicationDataMessages = maxDeferredProcessedApplicationDataMessages;
			return this;
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
			}
			config.maxConnections = maxConnections;
			return this;
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
			}
			config.staleConnectionThreshold = threshold;
			return this;
		}

		/**
		 * Sets the connection id generator.
		 * 
		 * @param connectionIdGenerator connection id generator. {@code null}
		 *            for not supported. The generator may only support the use
		 *            of a connection id without using it by itself. In that
		 *            case {@link ConnectionIdGenerator#useConnectionId()} must
		 *            return {@code false}.
		 * @return this builder for command chaining.
		 */
		public Builder setConnectionIdGenerator(ConnectionIdGenerator connectionIdGenerator) {
			config.connectionIdGenerator = connectionIdGenerator;
			return this;
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
		 * The default value is {@code null}, for no automatic session
		 * resumption. The configured value may be overridden by the endpoint
		 * context attribute {@link DtlsEndpointContext#KEY_RESUMPTION_TIMEOUT}.
		 * 
		 * @param timeoutInMillis the number of milliseconds. Usually values
		 *            around 30000 milliseconds are useful, depending on the
		 *            setup of NATS on the path. Smaller timeouts are only
		 *            useful for unit test, they would trigger too many
		 *            resumption handshakes.
		 * @return this builder for command chaining.
		 * @throws IllegalArgumentException if the timeout is below 1
		 *             millisecond
		 */
		public Builder setAutoResumptionTimeoutMillis(Long timeoutInMillis) {
			if (timeoutInMillis != null && timeoutInMillis < 1) {
				throw new IllegalArgumentException("auto resumption timeout must not below 1!");
			}
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
		 * Sets threshold in percent of {@link #setMaxConnections(int)}, whether
		 * a HELLO_VERIFY_REQUEST should be used also for session resumption.
		 * 
		 * Note: a value larger than 0 will call
		 * {@link SessionCache#get(org.eclipse.californium.scandium.dtls.SessionId)}.
		 * If that implementation is expensive, please ensure, that this value
		 * is configured with {@code 0}. Otherwise, CLIENT_HELLOs with invalid
		 * session ids may be spoofed and gets too expensive.
		 * 
		 * @param threshold 0 := always use HELLO_VERIFY_REQUEST, 1 ... 100 :=
		 *            dynamically determine to use HELLO_VERIFY_REQUEST. Default
		 *            is based on
		 *            {@link DtlsConnectorConfig#DEFAULT_VERIFY_PEERS_ON_RESUMPTION_THRESHOLD_IN_PERCENT}
		 * @return this builder for command chaining.
		 * @throws IllegalArgumentException if threshold is not between 0 and 100
		 * @see DtlsConnectorConfig#verifyPeersOnResumptionThreshold
		 */
		public Builder setVerifyPeersOnResumptionThreshold(int threshold) {
			if (threshold < 0 || threshold > 100) {
				throw new IllegalArgumentException("threshold must be between 0 and 100, but is " + threshold + "!");
			}
			config.verifyPeersOnResumptionThreshold = threshold;
			return this;
		}

		/**
		 * Set whether session id is used by this server or not.
		 * 
		 * @param flag {@code true} if no session id is used by this server.
		 * @return this builder for command chaining.
		 * @throws IllegalArgumentException if no session id should be used and
		 *             the configuration is for client only.
		 */
		public Builder setNoServerSessionId(boolean flag) {
			if (clientOnly && flag) {
				throw new IllegalArgumentException("not applicable for client only!");
			}
			config.useNoServerSessionId = flag;
			return this;
		}

		/**
		 * Use anti replay filter.
		 * 
		 * @param enable {@code true} to enable filter. Default {@code true}.
		 * @return this builder for command chaining.
		 * @throws IllegalArgumentException if window filter is active.
		 * @see http://tools.ietf.org/html/rfc6347#section-4.1
		 */
		public Builder setUseAntiReplayFilter(boolean enable) {
			if (enable && Boolean.TRUE.equals(config.useWindowFilter)) {
				throw new IllegalArgumentException("Window filter is active!");
			}
			config.useAntiReplayFilter = enable;
			return this;
		}

		/**
		 * Use window filter.
		 * 
		 * Messages too old for the filter window will pass the filter.
		 * 
		 * @param enable {@code true} to enable filter. Default {@code false}.
		 * @return this builder for command chaining.
		 * @throws IllegalArgumentException if anti replay window filter is active.
		 * @see http://tools.ietf.org/html/rfc6347#section-4.1
		 */
		public Builder setUseWindowFilter(boolean enable) {
			if (enable && Boolean.TRUE.equals(config.useAntiReplayFilter)) {
				throw new IllegalArgumentException("Anti replay filter is active!");
			}
			config.useWindowFilter = enable;
			return this;
		}

		/**
		 * Set instance logging tag.
		 * 
		 * @param tag logging tag of configure instance
		 * @return this builder for command chaining.
		 */
		public Builder setLoggingTag(String tag) {
			config.loggingTag = tag;
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
			if (config.loggingTag == null) {
				config.loggingTag = "";
			}
			if (config.enableReuseAddress == null) {
				config.enableReuseAddress = false;
			}
			if (config.earlyStopRetransmission == null) {
				config.earlyStopRetransmission = true;
			}
			if (config.retransmissionTimeout == null) {
				config.retransmissionTimeout = DEFAULT_RETRANSMISSION_TIMEOUT_MS;
			}
			if (config.maxRetransmissions == null) {
				config.maxRetransmissions = DEFAULT_MAX_RETRANSMISSIONS;
			}
			if (config.maxFragmentedHandshakeMessageLength == null) {
				config.maxFragmentedHandshakeMessageLength = DEFAULT_MAX_FRAGMENTED_HANDSHAKE_MESSAGE_LENGTH;
			}
			if (config.clientAuthenticationWanted == null) {
				config.clientAuthenticationWanted = false;
			}
			if (config.clientAuthenticationRequired == null) {
				if (clientOnly) {
					config.clientAuthenticationRequired = false;
				} else {
					config.clientAuthenticationRequired = !config.clientAuthenticationWanted;
				}
			}
			if (config.serverOnly == null) {
				config.serverOnly = false;
			}
			if (config.useNoServerSessionId == null) {
				config.useNoServerSessionId = false;
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
			if (config.sniEnabled == null) {
				config.sniEnabled = Boolean.FALSE;
			}
			if (config.useAntiReplayFilter == null) {
				config.useAntiReplayFilter = !Boolean.TRUE.equals(config.useWindowFilter);
			}
			if (config.useWindowFilter == null) {
				config.useWindowFilter = false;
			}
			if (config.verifyPeersOnResumptionThreshold == null) {
				config.verifyPeersOnResumptionThreshold = DEFAULT_VERIFY_PEERS_ON_RESUMPTION_THRESHOLD_IN_PERCENT;
			}
			if (config.certificateVerifier == null && config.trustStore != null) {
				config.certificateVerifier = new StaticCertificateVerifier(config.trustStore);
			}
			if (config.trustCertificateTypes == null) {
				if (config.trustedRPKs != null || config.certificateVerifier != null) {
					config.trustCertificateTypes = new ArrayList<>(2);
					if (config.trustedRPKs != null) {
						config.trustCertificateTypes.add(CertificateType.RAW_PUBLIC_KEY);
					}
					if (config.certificateVerifier != null) {
						config.trustCertificateTypes.add(CertificateType.X_509);
					}
				}
			} 

			if (config.serverOnly && !config.clientAuthenticationRequired && !config.clientAuthenticationWanted
					&& config.trustCertificateTypes != null) {
				throw new IllegalStateException(
						"configured trusted certificates or certificate verifier are not used for disabled client authentication!");
			}

			if (config.supportedCipherSuites == null || config.supportedCipherSuites.isEmpty()) {
				determineCipherSuitesFromConfig();
			}

			// check cipher consistency
			if (config.supportedCipherSuites == null || config.supportedCipherSuites.isEmpty()) {
				throw new IllegalStateException("Supported cipher suites must be set either " +
						"explicitly or implicitly by means of setting the identity or PSK store");
			}
			for (CipherSuite cipherSuite : config.supportedCipherSuites) {
				if (!cipherSuite.isSupported()) {
					throw new IllegalStateException("cipher-suites " + cipherSuite + " is not supported by JVM!");
				}
			}

			if (config.trustCertificateTypes != null) {
				if (config.trustCertificateTypes.contains(CertificateType.RAW_PUBLIC_KEY)) {
					if (config.trustedRPKs == null) {
						throw new IllegalStateException(
								"rpk trust must be set for trust certificate type RAW_PUBLIC_KEY");
					}
				}
				if (config.trustCertificateTypes.contains(CertificateType.X_509)) {
					if (config.certificateVerifier == null) {
						throw new IllegalStateException(
								"trusted certificates or certificate verifier must be set for trust certificate type X_509");
					}
				}
			}

			boolean certifacte = false;
			boolean psk = false;
			for (CipherSuite suite : config.supportedCipherSuites) {
				if (suite.isPskBased()) {
					verifyPskBasedCipherConfig(suite);
					psk = true;
				} else if (suite.requiresServerCertificateMessage()) {
					verifyCertificateBasedCipherConfig(suite);
					certifacte = true;
				}
			}

			if (!psk && config.pskStore != null) {
				throw new IllegalStateException("PSK store set, but no PSK cipher suite!");
			}

			if (!certifacte) {
				if (config.privateKey != null || config.publicKey != null) {
					throw new IllegalStateException("Identity set, but no certificate based cipher suite!");
				}
				if (config.trustedRPKs != null || config.certificateVerifier != null) {
					throw new IllegalStateException("certificate trust set, but no certificate based cipher suite!");
				}
			}

			config.trustCertificateTypes = ListUtils.init(config.trustCertificateTypes);
			config.identityCertificateTypes = ListUtils.init(config.identityCertificateTypes);
			config.supportedCipherSuites = ListUtils.init(config.supportedCipherSuites);
			config.certChain = ListUtils.init(config.certChain);

			return config;
		}

		private void verifyPskBasedCipherConfig(CipherSuite suite) {
			if (config.pskStore == null) {
				throw new IllegalStateException("PSK store must be set for configured " + suite.name());
			}
		}

		private void verifyCertificateBasedCipherConfig(CipherSuite suite) {
			if (config.privateKey == null || config.publicKey == null) {
				if (!clientOnly) {
					throw new IllegalStateException("Identity must be set for configured " + suite.name());
				}
			} else {
				String algorithm = suite.getCertificateKeyAlgorithm().name();
				if (!algorithm.equals(config.privateKey.getAlgorithm())
						|| !algorithm.equals(config.publicKey.getAlgorithm())) {
					throw new IllegalStateException(
							"Keys must be " + algorithm + " capable for configured " + suite.name());
				}
			}
			if (clientOnly || config.clientAuthenticationRequired || config.clientAuthenticationWanted) {
				if (config.trustCertificateTypes == null) {
					throw new IllegalStateException("trust must be set for configured " + suite.name());
				}
				if (config.trustCertificateTypes.contains(CertificateType.RAW_PUBLIC_KEY)) {
					if (config.trustedRPKs == null) {
						throw new IllegalStateException(
								"Raw public key trust must be set for configured " + suite.name());
					}
				}
				if (config.trustCertificateTypes.contains(CertificateType.X_509)) {
					if (config.certificateVerifier == null) {
						throw new IllegalStateException(
								"X509 certficate trust must be set for configured " + suite.name());
					}
				}
			}
		}

		private void determineCipherSuitesFromConfig() {
			// user has not explicitly set cipher suites
			// try to guess his intentions from properties he has set
			List<CipherSuite> ciphers = new ArrayList<>();
			boolean certificates = isConfiguredWithKeyPair() || config.trustCertificateTypes != null;

			if (certificates) {
				// currently only ECDSA is supported!
				ciphers.addAll(CipherSuite.getEcdsaCipherSuites(extendedCipherSuites));
			}

			if (config.pskStore != null) {
				ciphers.addAll(CipherSuite.getPskCipherSuites(extendedCipherSuites, true));
			}

			config.supportedCipherSuites = ciphers;
		}
	}
}