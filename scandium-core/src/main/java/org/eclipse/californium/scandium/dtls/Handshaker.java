/*******************************************************************************
 * Copyright (c) 2015, 2019 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 464383
 *    Kai Hudalla (Bosch Software Innovations GmbH) - replace custom HMAC implementation
 *                                                    with standard algorithm
 *    Kai Hudalla (Bosch Software Innovations GmbH) - retrieve security parameters from cipher suite only
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add support for notifying a SessionListener about
 *                                                    life-cycle events
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use SortedSet for buffering fragmented messages in order
 *                                                    to avoid repetitive sorting
 *    Kai Hudalla (Bosch Software Innovations GmbH) - consolidate and fix record buffering and message re-assembly
 *    Kai Hudalla (Bosch Software Innovations GmbH) - replace local compressionMethod and cipherSuite properties
 *                                                    with corresponding properties in DTLSSession
 *    Kai Hudalla (Bosch Software Innovations GmbH) - derive max fragment length from network MTU
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use SessionListener to trigger sending of pending
 *                                                    APPLICATION messages
 *    Bosch Software Innovations GmbH - move PRF code to separate PseudoRandomFunction class
 *    Achim Kraus (Bosch Software Innovations GmbH) - add handshakeFailed to report
 *                                                    handshake errors.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use LinkedHashSet to order listeners
 *                                                    see issue #406
 *    Ludwig Seitz (RISE SICS) - Moved certificate validation here from CertificateMessage
 *    Ludwig Seitz (RISE SICS) - Added support for raw public key validation
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - issue #549
 *                                                    trustStore := null, disable x.509
 *                                                    trustStore := [], enable x.509, trust all
 *    Vikram (University of Rostock) - generatePremasterSecertFromPSK with otherSecret from ECDHE_PSK
 *    Achim Kraus (Bosch Software Innovations GmbH) - use handshake parameter and
 *                                                    generic handshake messages to
 *                                                    process reordered handshake messages
 *                                                    and create the specific, when the parameters
 *                                                    are available.
 *    Achim Kraus (Bosch Software Innovations GmbH) - issue 744: use handshaker as
 *                                                    parameter for session listener.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add handshakeFlightRetransmitted
 *    Achim Kraus (Bosch Software Innovations GmbH) - redesign connection session listener to
 *                                                    ensure, that the session listener methods
 *                                                    are called via the handshaker.
 *    Achim Kraus (Bosch Software Innovations GmbH) - suppress duplicates only from
 *                                                    the same epoch
 *    Achim Kraus (Bosch Software Innovations GmbH) - redesign DTLSFlight and RecordLayer
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove copy of master secret
 *    Achim Kraus (Bosch Software Innovations GmbH) - redesign wrapMessage
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.auth.AdditionalInfo;
import org.eclipse.californium.elements.auth.ExtensiblePrincipal;
import org.eclipse.californium.elements.auth.PreSharedKeyIdentity;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.elements.util.SerialExecutor;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.auth.ApplicationLevelInfoSupplier;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.CertificateKeyAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction.Label;
import org.eclipse.californium.scandium.dtls.cipher.RandomManager;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedPskStore;
import org.eclipse.californium.scandium.dtls.x509.CertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.NewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.util.SecretIvParameterSpec;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A base class for the DTLS handshake protocol.
 * 
 * Contains functionality and fields needed by all types of handshakers.
 */
public abstract class Handshaker implements Destroyable {

	protected final Logger LOGGER = LoggerFactory.getLogger(getClass());

	protected Random clientRandom;
	protected Random serverRandom;

	/**
	 * Seed for master secret.
	 * 
	 * @since 3.0
	 */
	private byte[] masterSecretSeed;

	/**
	 * The master secret for this handshake.
	 */
	private SecretKey masterSecret;
	private SecretKey clientWriteMACKey;
	private SecretKey serverWriteMACKey;

	private SecretKey clientWriteKey;
	private SecretKey serverWriteKey;

	private SecretIvParameterSpec clientWriteIV;
	private SecretIvParameterSpec serverWriteIV;

	private volatile boolean generateClusterMacKeys;

	private boolean destroyed;

	private final ReentrantLock recursionProtection = new ReentrantLock();

	/**
	 * Communication over IPv6.
	 * 
	 * @since 2.4
	 */
	private final boolean ipv6;
	/**
	 * DTLS context of handshaker.
	 */
	private final DTLSContext context;

	/**
	 * The logic in charge of verifying the chain of certificates asserting this
	 * handshaker's identity
	 */
	protected final NewAdvancedCertificateVerifier certificateVerifier;

	/** Used to retrieve identity/pre-shared-key for a given destination */
	protected final AdvancedPskStore advancedPskStore;

	/**
	 * The configured connection id length. {@code null}, not supported,
	 * {@code 0} supported but not used.
	 */
	protected final ConnectionIdGenerator connectionIdGenerator;

	/**
	 * The current handshake message sequence number (in the handshake message
	 * called message_seq) for outgoing messages of this handshake.
	 */
	private int sendMessageSequence = 0;

	/**
	 * The next expected handshake message sequence number (in the handshake
	 * message called message_seq) for incoming messages of this handshake.
	 */
	private int nextReceiveMessageSequence = 0;

	/** Realtime nanoseconds of last sending a flight */
	private long flightSendNanos;

	/** Realtime nanoseconds when handshakes get's expired. */
	private long nanosExpireTime;

	/** Timeout in nanoseconds to expire handshakes. */
	private final long nanosExpireTimeout;

	/** The current flight number. */
	protected int flightNumber = 0;
	/**
	 * Record size limit. {@code null}, if not used.
	 * @since 2.4
	 */
	protected Integer recordSizeLimit;

	/**
	 * Accumulated record size of deferred incoming records.
	 * 
	 * @see #addDeferredProcessedRecord(Record, Collection)
	 * @see #removeDeferredProcessedRecord(Record, Collection)
	 */
	private int deferredIncomingRecordsSize;

	/** Maximum length of reassembled fragmented handshake messages */
	private final int maxFragmentedHandshakeMessageLength;
	/** Maximum number of outgoing application data messages, which may be processed deferred after the handshake */
	private final int maxDeferredProcessedOutgoingApplicationDataMessages;
	/** Maximum number of bytes of deferred processed incoming records */
	private final int maxDeferredProcessedIncomingRecordsSize;
	/** List of application data messages, which are send deferred after the handshake */
	private final List<RawData> deferredApplicationData = new ArrayList<RawData>();
	/**
	 * List of received records of next epoch.
	 * 
	 * Records are processed deferred after the epoch changed or the handshake
	 * failed.
	 * 
	 * @since 3.0 (renamed, was deferredRecords)
	 */
	private final List<Record> nextEpochDeferredRecords = new ArrayList<Record>();
	/** Currently pending flight */
	private final AtomicReference<DTLSFlight> pendingFlight = new AtomicReference<DTLSFlight>();
	/**
	 * Task to retransmit flight.
	 * 
	 * @since 2.4
	 */
	private Runnable retransmitFlight;
	/**
	 * Future of completion timeout of the last flight.
	 * 
	 * This future indicates, that the last flight of the handshake is pending.
	 * The last flight is not retransmitted by the retransmission timeout, it's
	 * retransmitted, if the other peer retransmits the flight before this.
	 * 
	 * If no data is received within that completion timeout, the handshake is
	 * completed without. The last flight is not longer kept, because the other
	 * peer is not longer considered to retransmit its flight before this.
	 * 
	 * @since 3.0
	 */
	private ScheduledFuture<?> timeoutLastFlight;

	/**
	 * Scheduler for flight timeout and retransmission.
	 * 
	 * @since 2.4
	 */
	private final ScheduledExecutorService timer;
	/**
	 * Record layer to send messages.
	 */
	private final RecordLayer recordLayer;
	/**
	 * Associated connection for this handshaker.
	 */
	private final Connection connection;

	/** Buffer for received records that can not be processed immediately. */
	private InboundMessageBuffer inboundMessageBuffer;

	protected final Object peerToLog;
	/** List of handshake messages */
	protected final List<HandshakeMessage> handshakeMessages = new ArrayList<HandshakeMessage>();

	/**
	 * Current partial reassembled handshake message.
	 */
	private ReassemblingHandshakeMessage reassembledMessage;
	/**
	 * The handshaker's certificate identity provider.
	 * 
	 * @since 3.0
	 */
	protected final CertificateProvider certificateIdentityProvider;
	/**
	 * The handshaker's private key.
	 * 
	 * Only available after certificate identity is provided. May be
	 * {@code null}, if no matching identity is available.
	 */
	protected PrivateKey privateKey;
	/**
	 * The handshaker's public key.
	 * 
	 * Only available after certificate identity is provided. May be
	 * {@code null}, if no matching identity is available.
	 */
	protected PublicKey publicKey;
	/**
	 * The chain of certificates asserting this handshaker's identity.
	 * 
	 * Only available after certificate identity is provided. May be
	 * {@code null}, if no matching identity is available.
	 */
	protected List<X509Certificate> certificateChain;
	/**
	 * The certificate path of the other peer.
	 * 
	 * Only available after certificate verification. Optionally truncated to
	 * trusted issuer.
	 * 
	 * @since 3.0 (renamed, was peerCertPath)
	 */
	private CertPath otherPeersCertPath;
	/**
	 * The public key of the other peer
	 * 
	 * May be {@code null}, if other peer sends a empty certificate.
	 *  
	 * @since 3.0
	 */
	protected PublicKey otherPeersPublicKey;
	/**
	 * Indicates, that the verification of the other peer's certificate chain public key has finished.
	 * 
	 * @since 3.0 (renamed certificateVerfied)
	 */
	protected boolean otherPeersCertificateVerified;
	/**
	 * Indicates, that the signature of the other peers is verified.
	 * 
	 * That signature is contained in the SERVER_KEY_EXCHANGE or CERTIFICATE_VERIFY. 
	 * 
	 * @since 3.0
	 */
	private boolean otherPeersSignatureVerified;

	/**
	 * Support Server Name Indication TLS extension.
	 */
	protected final boolean sniEnabled;

	/**
	 * Send the extended master secret extension.
	 * 
	 * @since 3.0
	 */
	protected final ExtendedMasterSecretMode extendedMasterSecretMode;

	/**
	 * Truncate certificate path for validation.
	 */
	protected final boolean useTruncatedCertificatePathForVerification;

	/**
	 * Stop retransmission with receiving the first record of the answer flight.
	 * 
	 * @since 2.4
	 */
	private final boolean useEarlyStopRetransmission;

	/**
	 * Use datagrams with multiple dtls records.
	 * 
	 * @since 2.4
	 */
	private Boolean useMultiRecordMessages;
	/**
	 * Use dtls records with multiple handshake messages.
	 * 
	 * @since 2.4
	 */
	private Boolean useMultiHandshakeMessagesRecord;
	/**
	 * Back-off retransmission.
	 * 
	 * @since 2.4
	 */
	private final int backOffRetransmission;
	/**
	 * Maximum number of retransmissions.
	 * 
	 * @since 2.4
	 */
	private final int maxRetransmissions;
	/**
	 * Retransmission timeout.
	 * 
	 * @since 2.4
	 */
	private final int retransmissionTimeout;
	/**
	 * Maximum retransmission timeout.
	 * 
	 * @since 3.0
	 */
	private final int maxRetransmissionTimeout;
	private final float retransmissionRandomFactor;
	private final float retransmissionTimeoutScale;
	/**
	 * Additional timeout for ECC.
	 * 
	 * @since 3.0
	 */
	private final int additionalTimeoutForEcc;
	/**
	 * Session listeners.
	 * 
	 * @see #addSessionListener(SessionListener)
	 */
	private final Set<SessionListener> sessionListeners = new LinkedHashSet<>();

	/**
	 * Indicates, that {@link #setExpectedStates(HandshakeState[])} has been called
	 * during the last processing of {@link #processNextHandshakeMessages}.
	 * 
	 * @since 3.0
	 */
	private boolean statesChanged;
	/**
	 * Current index of {@link #expectedStates}.
	 */
	private int statesIndex;
	/**
	 * Currently expected states.
	 * 
	 * @see #statesIndex
	 * @see #setExpectedStates(HandshakeState[])
	 * @since 3.0 (renamed, was states)
	 */
	private HandshakeState[] expectedStates;

	private boolean eccExpected;
	private boolean changeCipherSuiteMessageExpected;
	private boolean contextEstablished;
	private boolean handshakeCompleted;
	private boolean handshakeAborted;
	private boolean handshakeFailed;
	private boolean pskRequestPending;
	private boolean certificateVerificationPending;
	private boolean certificateIdentityPending;
	/**
	 * {@code true}, if the certificate identity request has completed,
	 * {@code false}, otherwise. Gets {@code true}, even if no matching identity
	 * is available.
	 * 
	 * @since 3.0
	 */
	protected boolean certificateIdentityAvailable;

	/**
	 * Other secret for ECDHE-PSK cipher suites.
	 * <a href="https://tools.ietf.org/html/rfc5489#page-4" target="_blank"> RFC 5489, other
	 * secret</a>
	 */
	private SecretKey otherSecret;
	/**
	 * Cause for handshake failure.
	 * 
	 * @see #setFailureCause(Throwable)
	 */
	private Throwable cause;
	/**
	 * Custom argument for {@link ApplicationLevelInfoSupplier#getInfo(Principal, Object)}.
	 * 
	 * @since 2.3
	 */
	private Object customArgument;
	/**
	 * Application level info supplier. May be {@code null}.
	 */
	private ApplicationLevelInfoSupplier applicationLevelInfoSupplier;

	/**
	 * Creates a new handshaker for negotiating a DTLS session with a given
	 * peer.
	 * 
	 * @param initialRecordSequenceNo the initial record sequence number (since 3.0).
	 * @param initialMessageSeq the initial message sequence number to use and
	 *            expect in the exchange of handshake messages with the peer.
	 *            This parameter can be used to initialize the
	 *            <em>message_seq</em> and <em>receive_next_seq</em> counters to
	 *            a value larger than 0, e.g. if one or more cookie exchange
	 *            round-trips have been performed with the peer before the
	 *            handshake starts.
	 * @param recordLayer the object to use for sending flights to the peer.
	 * @param timer scheduled executor for flight retransmission (since 2.4).
	 * @param connection the connection related to this handshaker.
	 * @param config the dtls configuration
	 * @throws NullPointerException if any of the provided parameter is
	 *             {@code null}
	 * @throws IllegalArgumentException if the initial record or message sequence number
	 *             is negative
	 */
	@NoPublicAPI
	protected Handshaker(long initialRecordSequenceNo, int initialMessageSeq, RecordLayer recordLayer,
			ScheduledExecutorService timer, Connection connection, DtlsConnectorConfig config) {
		if (recordLayer == null) {
			throw new NullPointerException("Record layer must not be null");
		} else if (timer == null) {
			throw new NullPointerException("Timer must not be null");
		} else if (connection == null) {
			throw new NullPointerException("Connection must not be null");
		} else if (config == null) {
			throw new NullPointerException("Dtls Connector Config must not be null");
		} else if (initialMessageSeq < 0) {
			throw new IllegalArgumentException("Initial message sequence number must not be negative");
		} else if (initialRecordSequenceNo < 0) {
			throw new IllegalArgumentException("Initial record sequence number must not be negative");
		}
		this.sendMessageSequence = initialMessageSeq;
		this.nextReceiveMessageSequence = initialMessageSeq;
		this.context = new DTLSContext(initialRecordSequenceNo);
		this.recordLayer = recordLayer;
		this.timer = timer;
		this.connection = connection;
		this.peerToLog = StringUtil.toLog(connection.getPeerAddress());
		this.connectionIdGenerator = config.getConnectionIdGenerator();
		this.retransmissionTimeout = config.getRetransmissionTimeout();
		this.maxRetransmissionTimeout = config.getMaxRetransmissionTimeout();
		this.additionalTimeoutForEcc = config.getAdditionalTimeoutForEcc();
		this.retransmissionRandomFactor = config.getRetransmissionRandomFactor();
		this.retransmissionTimeoutScale = config.getRetransmissionTimeoutScale();
		this.backOffRetransmission = config.getBackOffRetransmission();
		this.maxRetransmissions = config.getMaxRetransmissions();
		this.recordSizeLimit = config.getRecordSizeLimit();
		this.maxFragmentedHandshakeMessageLength = config.getMaxFragmentedHandshakeMessageLength();
		this.useMultiRecordMessages = config.useMultiRecordMessages();
		this.useMultiHandshakeMessagesRecord = config.useMultiHandshakeMessageRecords();
		this.maxDeferredProcessedOutgoingApplicationDataMessages = config.getMaxDeferredProcessedOutgoingApplicationDataMessages();
		this.maxDeferredProcessedIncomingRecordsSize = config.getMaxDeferredProcessedIncomingRecordsSize();
		this.sniEnabled = config.useServerNameIndication();
		this.extendedMasterSecretMode = config.getExtendedMasterSecretMode();
		this.useTruncatedCertificatePathForVerification = config.useTruncatedCertificatePathForValidation();
		this.useEarlyStopRetransmission = config.useEarlyStopRetransmission();
		this.certificateIdentityProvider = config.getCertificateIdentityProvider();
		this.certificateVerifier = config.getAdvancedCertificateVerifier();
		this.advancedPskStore = config.getAdvancedPskStore();
		this.applicationLevelInfoSupplier = config.getApplicationLevelInfoSupplier();
		this.inboundMessageBuffer = new InboundMessageBuffer();
		this.ipv6 = connection.getPeerAddress().getAddress() instanceof Inet6Address;
		// add all timeouts for retries and the initial timeout twice
		// to get a short extra timespan for regular handshake timeouts
		int timeoutMillis = Math.round(retransmissionTimeout * retransmissionRandomFactor);
		if (CipherSuite.containsEccBasedCipherSuite(config.getSupportedCipherSuites())) {
			timeoutMillis += additionalTimeoutForEcc;
		}
		timeoutMillis = Math.min(timeoutMillis, maxRetransmissionTimeout);
		int expireTimeoutMillis = Math.min(Math.round(timeoutMillis * retransmissionTimeoutScale),
				maxRetransmissionTimeout);
		for (int retry = 0; retry < maxRetransmissions; ++retry) {
			timeoutMillis = DTLSFlight.incrementTimeout(timeoutMillis, retransmissionTimeoutScale,
					maxRetransmissionTimeout);
			expireTimeoutMillis += timeoutMillis;
		}
		this.nanosExpireTimeout = TimeUnit.MILLISECONDS.toNanos(expireTimeoutMillis);
		addSessionListener(connection.getSessionListener());
	}

	/**
	 * A queue for buffering inbound handshake records.
	 */
	private class InboundMessageBuffer {

		private Record changeCipherSpec = null;

		private SortedSet<Record> queue = new TreeSet<>(new Comparator<Record>() {

			@Override
			public int compare(Record r1, Record r2) {
				return compareRecords(r1, r2);
			}
		});

		boolean isEmpty() {
			return queue.isEmpty();
		}

		/**
		 * Gets (and removes from the queue) the next record of the handshake
		 * message with this handshake's next expected message sequence number.
		 * 
		 * @return the record or {@code null} if the queue does not contain the
		 *         next expected message (yet)
		 */
		Record getNextRecord() {

			if (isChangeCipherSpecMessageExpected() && changeCipherSpec != null) {
				Record result = changeCipherSpec;
				changeCipherSpec = null;
				return result;
			} else {
				while (!queue.isEmpty()) {
					Record record = queue.first();
					int messageSeq = ((HandshakeMessage) record.getFragment()).getMessageSeq();
					if (messageSeq > nextReceiveMessageSequence) {
						break;
					}
					removeDeferredProcessedRecord(record, queue);
					if (messageSeq == nextReceiveMessageSequence) {
						return record;
					}
				}
			}

			return null;
		}

		/**
		 * Checks if a given record contains a message that can be processed
		 * immediately as part of the ongoing handshake.
		 * <p>
		 * This is the case, if the record is from the <em>current read
		 * epoch</em> and the contained message is either a
		 * <em>CHANGE_CIPHER_SPEC</em> message or a <em>HANDSHAKE</em> message
		 * with the next expected sequence number.
		 * <p>
		 * If the record contains a message having a sequence number that is
		 * higher than the next expected one, the record is put into a buffer
		 * for later processing when the message's sequence number becomes the
		 * next expected one.
		 * 
		 * @param candidate the candidate record containing the message to check
		 * @return the record containing a message if the message is up for
		 *         immediate processing or {@code null}, if the message cannot
		 *         be processed immediately
		 * @throws IllegalArgumentException if the record's epoch differs from
		 *             the session's read epoch
		 */
		Record getNextRecord(Record candidate) {
			int recordEpoch = candidate.getEpoch();
			int contextEpoch = context.getReadEpoch();
			if (recordEpoch == contextEpoch) {
				DTLSMessage fragment = candidate.getFragment();
				switch (fragment.getContentType()) {
				case CHANGE_CIPHER_SPEC:
					// the following cases are possible:
					// 1. the CCS message is the one we currently expect
					//    -> process it immediately
					// 2. the CCS message is NOT YET expected, i.e. we are still missing one of the
					//    messages that logically need to be processed BEFORE the CCS message
					//    -> stash the CCS message and process it immediately once the missing messages
					//       have been processed
					// 3. the FINISHED message is received BEFORE the CCS message
					//    -> stash the FINISHED message (note that the FINISHED message's epoch is
					//       current read epoch + 1 and thus will have been queued by the
					//       "else" branch below
					if (isChangeCipherSpecMessageExpected()) {
						return candidate;
					} else if (changeCipherSpec == null) {
						// store message for later processing
						LOGGER.debug("Change Cipher Spec is not expected and therefore kept for later processing!");
						changeCipherSpec = candidate;
						return null;
					} else {
						// already stored message for later processing
						LOGGER.debug("Change Cipher Spec is received again!");
						return null;
					}
				case HANDSHAKE:
					HandshakeMessage handshakeMessage = (HandshakeMessage) fragment;
					int messageSeq = handshakeMessage.getMessageSeq();
					if (messageSeq == nextReceiveMessageSequence) {
						return candidate;
					} else if (messageSeq > nextReceiveMessageSequence) {
						LOGGER.debug(
								"Queued newer {} message from current epoch, message_seq [{}] > next_receive_seq [{}]",
								handshakeMessage.getMessageType(),
								messageSeq,
								nextReceiveMessageSequence);
						addDeferredProcessedRecord(candidate, queue);
						return null;
					} else {
						LOGGER.debug("Discarding old {} message_seq [{}] < next_receive_seq [{}]",
								handshakeMessage.getMessageType(),
								messageSeq,
								nextReceiveMessageSequence);
						return null;
					}
				default:
					LOGGER.info("Cannot process message of type [{}], discarding...", fragment.getContentType());
					return null;
				}
			} else {
				throw new IllegalArgumentException("record epoch " + recordEpoch + " doesn't match dtls context " + contextEpoch);
			}
		}
	}

	/**
	 * Compare records by the handshake message sequence number and record
	 * sequence number
	 * 
	 * @param r1 first record to be compared
	 * @param r2 second record to be compared
	 * @return a negative integer, zero, or a positive integer as the first
	 *         record is before, equal to, or after the second.
	 */
	private static int compareRecords(Record r1, Record r2) {

		if (r1.getEpoch() != r2.getEpoch()) {
			throw new IllegalArgumentException(
					"records with different epoch! " + r1.getEpoch() + " != " + r2.getEpoch());
		}
		HandshakeMessage h1 = (HandshakeMessage) r1.getFragment();
		HandshakeMessage h2 = (HandshakeMessage) r2.getFragment();
		if (h1.getMessageSeq() < h2.getMessageSeq()) {
			return -1;
		} else if (h1.getMessageSeq() > h2.getMessageSeq()) {
			return 1;
		}
		if (r1.getSequenceNumber() < r2.getSequenceNumber()) {
			return -1;
		} else if (r1.getSequenceNumber() > r2.getSequenceNumber()) {
			return 1;
		}
		return 0;
	}

	/**
	 * Check, if inbound messages are all processed.
	 * 
	 * @return {@code true}, all inbound messages are processed, {@code false},
	 *         some inbound messages are pending.
	 * @since 2.1
	 */
	public boolean isInboundMessageProcessed() {
		return inboundMessageBuffer.isEmpty();
	}

	/**
	 * Processes a handshake record received from a peer based on the
	 * handshake's current state.
	 * 
	 * This method passes the messages into the {@link #inboundMessageBuffer} and
	 * delegates processing of the ordered messages to the
	 * {@link #doProcessMessage(HandshakeMessage)} method. If
	 * {@link ChangeCipherSpecMessage} is processed, the
	 * {@link #nextEpochDeferredRecords} are passed again to the {@link RecordLayer} to
	 * get decrypted and processed.
	 * 
	 * @param record the handshake record
	 * @throws HandshakeException if the record's plaintext fragment cannot be
	 *             parsed into a handshake message or cannot be processed
	 *             properly
	 * @throws IllegalArgumentException if the record's epoch differs from the
	 *             DTLS context's read epoch
	 */
	public final void processMessage(Record record) throws HandshakeException {
		int epoch = context.getReadEpoch();
		if (epoch != record.getEpoch()) {
			LOGGER.debug("Discarding {} message with wrong epoch received from peer [{}]:{}{}",
					record.getType(), record.getPeerAddress(), StringUtil.lineSeparator(), record);
			throw new IllegalArgumentException("processing record with wrong epoch! " + record.getEpoch() + " expected " + epoch);
		}
		if (pendingFlight.get() != null && (flightSendNanos - record.getReceiveNanos()) > 0) {
			// (see https://github.com/eclipse/californium/issues/1034#issuecomment-526656943)
			LOGGER.debug("Discarding {} message received from peer [{}] before last flight was sent:{}{}",
					record.getType(), record.getPeerAddress(), StringUtil.lineSeparator(), record);
			return;
		}
		Record recordToProcess = inboundMessageBuffer.getNextRecord(record);
		if (recordToProcess != null) {
			processNextMessages(recordToProcess);
		}
	}

	/**
	 * Process next messages.
	 * 
	 * Read next messages also from inbound message buffer. To protect against
	 * recursion, returns immediately, if called from
	 * {@link #doProcessMessage(HandshakeMessage)}.
	 * 
	 * @param record message to process. Maybe {@code null} to start with the
	 *            first message from inbound message buffer.
	 * @throws HandshakeException if an error occurs processing a message
	 * @since 2.3
	 */
	private void processNextMessages(Record record) throws HandshakeException {
		if (recursionProtection.isHeldByCurrentThread()) {
			LOGGER.warn("Called from doProcessMessage, return immediately to process next message!",
					new Throwable("recursion-protection"));
			return;
		}
		try {
			final int epoch = context.getReadEpoch();
			int bufferIndex = 0;
			Record recordToProcess = record != null ? record : inboundMessageBuffer.getNextRecord();
			while (recordToProcess != null) {
				if (useMultiRecordMessages == null && recordToProcess.isFollowUpRecord()) {
					useMultiRecordMessages = true;
				}
				DTLSMessage messageToProcess = recordToProcess.getFragment();

				if (messageToProcess.getContentType() == ContentType.CHANGE_CIPHER_SPEC) {
					expectMessage(messageToProcess);
					// is thrown during processing
					LOGGER.debug("Processing {} message from peer [{}]", messageToProcess.getContentType(),
							peerToLog);
					setCurrentReadState();
					++statesIndex;
					LOGGER.debug("Processed {} message from peer [{}]", messageToProcess.getContentType(),
							peerToLog);
				} else if (messageToProcess.getContentType() == ContentType.HANDSHAKE) {
					boolean more = processNextHandshakeMessages(recordToProcess.getEpoch(), bufferIndex, (HandshakeMessage) messageToProcess);
					context.markRecordAsRead(recordToProcess.getEpoch(), recordToProcess.getSequenceNumber());
					if (!more) {
						break;
					}
				} else {
					throw new HandshakeException(
							String.format("Received unexpected message type [%s] from peer %s",
									messageToProcess.getContentType(), peerToLog),
							new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE));
				}
				recordToProcess = inboundMessageBuffer.getNextRecord();
				if (epoch < context.getReadEpoch()) {
					if (recordToProcess != null || !inboundMessageBuffer.isEmpty()) {
						throw new HandshakeException(
								String.format("Unexpected handshake message left from peer %s", peerToLog),
								new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE));
					}
				}
				++bufferIndex;
			}
			if (epoch < context.getReadEpoch()) {
				final SerialExecutor serialExecutor = connection.getExecutor();
				final List<Record> records = takeDeferredRecordsOfNextEpoch();
				if (deferredIncomingRecordsSize > 0) {
					throw new HandshakeException(
							String.format("Received message of next epoch left from peer %s", peerToLog),
							new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR));
				}
				for (Record deferredRecord : records) {
					if (serialExecutor != null && !serialExecutor.isShutdown()) {
						try {
							final Record dRecord = deferredRecord;
							serialExecutor.execute(new Runnable() {

								@Override
								public void run() {
									recordLayer.processRecord(dRecord, connection);
								}
							});
							continue;
						} catch (RejectedExecutionException ex) {
							LOGGER.debug("Execution rejected while processing record [type: {}, peer: {}]",
									deferredRecord.getType(), deferredRecord.getPeerAddress(), ex);
						}
					}
					// shutdown or rejected
					recordLayer.processRecord(deferredRecord, connection);
				}
			}
		} catch (RuntimeException e) {
			LOGGER.warn("Cannot process handshake message from peer [{}] due to [{}]", peerToLog,
					e.getMessage(), e);
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR);
			throw new HandshakeException("Cannot process handshake message, caused by " + e.getMessage(), alert, e);
		}
	}

	/**
	 * Process next {@link HandshakeMessage}.
	 * 
	 * When {@link HandshakeMessage}s are chained, process all. To protected
	 * against recursion, returns immediately, if called from
	 * {@link #doProcessMessage(HandshakeMessage)}.
	 * 
	 * @param epoch epoch of the based record
	 * @param bufferIndex index within buffered handshake message. Used only for
	 *            logging.
	 * @param handshakeMessage the handshake message.
	 * @return {@code true}, continue processing record, {@code false}, stop
	 *         processing records.
	 * @throws HandshakeException if an error occurs processing a message
	 * @since 2.4
	 */
	private boolean processNextHandshakeMessages(int epoch, int bufferIndex, HandshakeMessage handshakeMessage)
			throws HandshakeException {
		if (recursionProtection.isHeldByCurrentThread()) {
			LOGGER.warn("Called from doProcessMessage, return immediately to process next message!",
					new Throwable("recursion-protection"));
			return false;
		}
		// only cancel on HANDSHAKE messages
		// the very last flight CCS + FINISH
		// must not be canceled before the FINISH
		DTLSFlight flight = pendingFlight.get();
		if (flight != null) {
			LOGGER.debug("response for flight {} started", flight.getFlightNumber());
			flight.setResponseStarted();
		}
		while (handshakeMessage != null) {
			expectMessage(handshakeMessage);
			if (handshakeMessage.getMessageType() == HandshakeType.FINISHED && epoch == 0) {
				LOGGER.debug("FINISH with epoch 0 from peer [{}]!", peerToLog);
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE);
				throw new HandshakeException("FINISH with epoch 0!", alert);
			}
			if (handshakeMessage instanceof FragmentedHandshakeMessage) {
				handshakeMessage = reassembleFragment((FragmentedHandshakeMessage) handshakeMessage);
				if (handshakeMessage == null) {
					break;
				}
			}
			if (handshakeMessage instanceof GenericHandshakeMessage) {
				GenericHandshakeMessage genericMessage = (GenericHandshakeMessage) handshakeMessage;
				handshakeMessage = HandshakeMessage.fromGenericHandshakeMessage(genericMessage, getParameter());
			}
			if (timeoutLastFlight != null) {
				if (flight == null) {
					if (cause != null) {
						LOGGER.error("last flight missing, handshake already failed! {}", handshakeMessage, cause);
					} else if (bufferIndex == 0) {
						LOGGER.error("last flight missing, resend failed! {}", handshakeMessage);
					} else {
						LOGGER.error("last flight missing, resend for buffered message {} failed! {}", bufferIndex,
								handshakeMessage);
					}
					return false;
				}
				// we already sent the last flight (including our FINISHED
				// message), but the other peer does not seem to have received
				// it because we received its finished message again, so we
				// simply retransmit our last flight
				LOGGER.debug("Received ({}) FINISHED message again, retransmitting last flight...", peerToLog);
				flight.incrementTries();
				// retransmit CCS and FINISH, back-off not required!
				sendFlight(flight);
				return false;
			} else {
				// is thrown during processing
				if (LOGGER.isDebugEnabled()) {
					StringBuilder msg = new StringBuilder();
					msg.append(String.format("Processing %s message from peer [%s], seqn: [%d]",
							handshakeMessage.getMessageType(), peerToLog,
							handshakeMessage.getMessageSeq()));
					if (LOGGER.isTraceEnabled()) {
						msg.append(":").append(StringUtil.lineSeparator()).append(handshakeMessage);
					}
					LOGGER.debug(msg.toString());
				}
				if (epoch == 0) {
					handshakeMessages.add(handshakeMessage);
				}
				statesChanged = false;
				recursionProtection.lock();
				try {
					doProcessMessage(handshakeMessage);
				} finally {
					recursionProtection.unlock();
				}
				LOGGER.debug("Processed {} message from peer [{}]", handshakeMessage.getMessageType(),
						peerToLog);
				if (timeoutLastFlight == null) {
					// last Flight may have changed processing
					// the handshake message
					++nextReceiveMessageSequence;
					if (!statesChanged) {
						++statesIndex;
					}
				}
				handshakeMessage = handshakeMessage.getNextHandshakeMessage();
				if (useMultiHandshakeMessagesRecord == null && handshakeMessage != null) {
					useMultiHandshakeMessagesRecord = true;
				}
			}
		}
		return true;
	}

	/**
	 * Checks, if the provided states are the currently expected ones.
	 * 
	 * @param states state to check
	 * @return {@code true}, if the provided states are the currently expected
	 *         ones
	 * @see #setExpectedStates(HandshakeState[])
	 * @since 3.0
	 */
	protected boolean isExpectedStates(HandshakeState[] states) {
		return this.expectedStates == states;
	}

	/**
	 * Sets expected states.
	 * 
	 * Resets {@link #statesIndex}.
	 * 
	 * @param states expected states
	 * @see #isExpectedStates(HandshakeState[])
	 * @see #expectMessage(DTLSMessage)
	 * @since 3.0
	 */
	protected void setExpectedStates(HandshakeState[] states) {
		this.expectedStates = states;
		this.statesIndex = 0;
		this.statesChanged = true;
	}

	/**
	 * Check, if message is expected.
	 * 
	 * @param message message to check
	 * @throws HandshakeException if the message is not expected
	 */
	protected void expectMessage(DTLSMessage message) throws HandshakeException {
		if (expectedStates == null) {
			LOGGER.warn("Cannot process {} message from peer [{}], not expected!", HandshakeState.toString(message),
					peerToLog);
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR);
			throw new HandshakeException("Cannot process " + HandshakeState.toString(message)
					+ " handshake message, not expected!", alert);
		}
		if (expectedStates.length == 0) {
			// only for tests!
			return;
		}
		if (statesIndex >= expectedStates.length) {
			LOGGER.warn("Cannot process {} message from peer [{}], no more expected!", HandshakeState.toString(message),
					peerToLog);
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR);
			throw new HandshakeException("Cannot process " + HandshakeState.toString(message)
					+ " handshake message, no more expected!", alert);
		}
		HandshakeState expectedState = expectedStates[statesIndex];
		boolean expected = expectedState.expect(message);
		if (!expected && expectedState.isOptional()) {
			if (statesIndex + 1 < expectedStates.length) {
				HandshakeState nextExpectedState = expectedStates[statesIndex + 1];
				if (nextExpectedState.expect(message)) {
					++statesIndex;
					expected = true;
				}
			}
		}

		if (!expected) {
			// check for self addressed messages
			// some cloud deployments may get easily mixed up
			DTLSFlight flight = pendingFlight.get();
			if (flight != null && flight.contains(message)) {
				LOGGER.debug("Cannot process {} message from itself [{}]!",
						HandshakeState.toString(message), peerToLog);
			} else {
				LOGGER.debug("Cannot process {} message from peer [{}], {} expected!",
						HandshakeState.toString(message), peerToLog, expectedState);
			}
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE);
			throw new HandshakeException("Cannot process " + HandshakeState.toString(message)
					+ " handshake message, " + expectedState + " expected!", alert);
		}
	}

	/**
	 * Does the specific processing of a message received from a peer in
	 * the course of an ongoing handshake.
	 * 
	 * This method does not do anything. Concrete handshaker implementations should
	 * override this method in order to prepare the response to the received
	 * record.
	 * 
	 * @param message the message received from the peer
	 * @throws HandshakeException if the handshake message cannot be processed properly
	 */
	protected abstract void doProcessMessage(HandshakeMessage message) throws HandshakeException;

	/**
	 * Process asynchronous handshake result.
	 * 
	 * MUST not be called from {@link #doProcessMessage(HandshakeMessage)}
	 * implementations! If handshake expects the cipher change message, then
	 * process the messages from the inbound buffer.
	 * 
	 * @param handshakeResult asynchronous handshake result
	 * @throws HandshakeException if an error occurs
	 * @throws IllegalStateException if {@link #pskRequestPending} or
	 *             {@link #certificateVerificationPending} is not pending, or
	 *             the handshaker {@link #isDestroyed()}.
	 * @since 2.5
	 */
	public void processAsyncHandshakeResult(HandshakeResult handshakeResult) throws HandshakeException {
		if (handshakeResult instanceof PskSecretResult) {
			processPskSecretResult((PskSecretResult) handshakeResult);
		} else if (handshakeResult instanceof CertificateVerificationResult) {
			processCertificateVerificationResult((CertificateVerificationResult) handshakeResult);
		} else if (handshakeResult instanceof CertificateIdentityResult) {
			processCertificateIdentityResult((CertificateIdentityResult) handshakeResult);
		}
		if (changeCipherSuiteMessageExpected) {
			processNextMessages(null);
		}
	}

	/**
	 * Process PSK secret result.
	 * 
	 * @param pskSecretResult PSK secret result.
	 * @throws HandshakeException if an error occurs
	 * @throws IllegalStateException if {@link #pskRequestPending} is not
	 *             pending, or the handshaker {@link #isDestroyed()}.
	 * @since 2.3
	 */
	protected void processPskSecretResult(PskSecretResult pskSecretResult) throws HandshakeException {
		if (!pskRequestPending) {
			throw new IllegalStateException("psk secret not pending!");
		}
		pskRequestPending = false;
		try {
			ensureUndestroyed();
			DTLSSession session = getSession();
			String hostName = sniEnabled ? session.getHostName() : null;
			PskPublicInformation pskIdentity = pskSecretResult.getPskPublicInformation();
			SecretKey newPskSecret = pskSecretResult.getSecret();
			if (newPskSecret != null) {
				if (hostName != null) {
					LOGGER.trace("client [{}] uses PSK identity [{}] for server [{}]", peerToLog, pskIdentity,
							hostName);
				} else {
					LOGGER.trace("client [{}] uses PSK identity [{}]", peerToLog, pskIdentity);
				}
				PreSharedKeyIdentity pskPrincipal;
				if (sniEnabled) {
					pskPrincipal = new PreSharedKeyIdentity(hostName, pskIdentity.getPublicInfoAsString());
				} else {
					pskPrincipal = new PreSharedKeyIdentity(pskIdentity.getPublicInfoAsString());
				}
				session.setPeerIdentity(pskPrincipal);
				if (PskSecretResult.ALGORITHM_PSK.equals(newPskSecret.getAlgorithm())) {
					Mac hmac = session.getCipherSuite().getThreadLocalPseudoRandomFunctionMac();
					SecretKey premasterSecret = PseudoRandomFunction.generatePremasterSecretFromPSK(otherSecret,
							newPskSecret);
					SecretKey masterSecret = PseudoRandomFunction.generateMasterSecret(hmac, premasterSecret,
							masterSecretSeed, session.useExtendedMasterSecret());
					SecretUtil.destroy(premasterSecret);
					SecretUtil.destroy(newPskSecret);
					newPskSecret = masterSecret;
				}
				setCustomArgument(pskSecretResult);
				applyMasterSecret(newPskSecret);
				SecretUtil.destroy(newPskSecret);
				processMasterSecret();
			} else {
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.UNKNOWN_PSK_IDENTITY);
				if (hostName != null) {
					throw new HandshakeException(
							String.format("No pre-shared key found for [virtual host: %s, identity: %s]", hostName,
									pskIdentity),
							alert);
				} else {
					throw new HandshakeException(
							String.format("No pre-shared key found for [identity: %s]", pskIdentity), alert);
				}
			}
		} finally {
			SecretUtil.destroy(otherSecret);
			otherSecret = null;
		}
	}

	/**
	 * Do the handshaker specific master secret processing
	 * 
	 * @throws HandshakeException if an error occurs
	 * @since 2.3
	 */
	protected abstract void processMasterSecret() throws HandshakeException;

	/**
	 * Process certificate verification result.
	 * 
	 * @param certificateVerificationResult certificate verification result
	 * @throws HandshakeException if an error occurred during processing
	 * @throws IllegalStateException if {@link #certificateVerificationPending}
	 *             is not pending, or the handshaker {@link #isDestroyed()}.
	 * @since 2.5
	 */
	protected void processCertificateVerificationResult(CertificateVerificationResult certificateVerificationResult)
			throws HandshakeException {
		if (!certificateVerificationPending) {
			throw new IllegalStateException("certificate verification not pending!");
		}
		ensureUndestroyed();
		certificateVerificationPending = false;
		LOGGER.debug("Process result of certificate verification.");
		if (certificateVerificationResult.getCertificatePath() != null) {
			otherPeersCertificateVerified = true;
			otherPeersCertPath = certificateVerificationResult.getCertificatePath();
			if (otherPeersSignatureVerified) {
				getSession().setPeerIdentity(new X509CertPath(otherPeersCertPath));
			}
			setCustomArgument(certificateVerificationResult);
			processCertificateVerified();
		} else if (certificateVerificationResult.getPublicKey() != null) {
			otherPeersCertificateVerified = true;
			if (otherPeersSignatureVerified) {
				getSession().setPeerIdentity(new RawPublicKeyIdentity(otherPeersPublicKey));
			}
			setCustomArgument(certificateVerificationResult);
			processCertificateVerified();
		} else if (certificateVerificationResult.getException() != null) {
			throw certificateVerificationResult.getException();
		} else {
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
			throw new HandshakeException("Bad Certificate", alert);
		}
	}

	/**
	 * Do the handshaker specific processing of successful verified certificates
	 * 
	 * @throws HandshakeException if an error occurs
	 * @since 2.5
	 */
	protected abstract void processCertificateVerified() throws HandshakeException;

	/**
	 * Process the certificate identity.
	 * 
	 * @param result certificate identity
	 * @throws HandshakeException if an error occurs
	 * @throws IllegalStateException if no call is pending (see
	 *             {@link #certificateIdentityPending}), or the handshaker
	 *             {@link #isDestroyed()}.
	 * @since 3.0
	 */
	protected void processCertificateIdentityResult(CertificateIdentityResult result) throws HandshakeException {
		if (!certificateIdentityPending) {
			throw new IllegalStateException("certificate identity not pending!");
		}
		ensureUndestroyed();
		certificateIdentityPending = false;
		LOGGER.debug("Process result of certificate identity.");
		this.privateKey = result.getPrivateKey();
		this.publicKey = result.getPublicKey();
		this.certificateChain = result.getCertificateChain();
		certificateIdentityAvailable = true;
		processCertificateIdentityAvailable();
	}

	/**
	 * Do the handshaker specific processing of certificate identity.
	 * 
	 * @throws HandshakeException if an error occurs
	 * @since 3.0
	 */
	protected abstract void processCertificateIdentityAvailable() throws HandshakeException;

	/**
	 * Set custom argument for {@link ApplicationLevelInfoSupplier}.
	 * 
	 * A {@code null} custom argument will not overwrite a already set one.
	 * 
	 * @param result handshake result with custom argument.
	 * @since 3.0
	 */
	protected void setCustomArgument(HandshakeResult result) {
		Object customArgument = result.getCustomArgument();
		if (customArgument != null) {
			this.customArgument = customArgument;
		}
	}

	/**
	 * Checks, if a internal API call is pending.
	 * 
	 * Using {@link AdvancedPskStore} or {@link NewAdvancedCertificateVerifier}
	 * may result in pending API calls. Such API calls are timed out with the
	 * current flight and so report as INTERNAL_ERROR alert instead of silently
	 * ignore that time out.
	 * 
	 * @return {@code true}, if call is pending, {@code false}, if not.
	 * @since 3.0
	 */
	protected boolean hasPendingApiCall() {
		return certificateIdentityPending || certificateVerificationPending || pskRequestPending;
	}

	/**
	 * Set the signature of the other peer to verified.
	 * 
	 * Sets the {@link DTLSSession#setPeerIdentity(Principal)}, if the
	 * certificate chain or public key of the other peer is also already
	 * verified.
	 * 
	 * @return the value of {@link #otherPeersCertificateVerified} 
	 * @since 3.0
	 */
	protected boolean setOtherPeersSignatureVerified() {
		otherPeersSignatureVerified = true;
		if (otherPeersCertificateVerified) {
			if (otherPeersCertPath != null) {
				getSession().setPeerIdentity(new X509CertPath(otherPeersCertPath));
			} else if (otherPeersPublicKey != null) {
				getSession().setPeerIdentity(new RawPublicKeyIdentity(otherPeersPublicKey));
			}
		}
		return otherPeersCertificateVerified;
	}

	/**
	 * Get message digest for FINISH message.
	 * 
	 * @return message digest update with all handshake messages in
	 *         {@link #handshakeMessages}
	 */
	protected final MessageDigest getHandshakeMessageDigest() {
		MessageDigest md = getSession().getCipherSuite().getThreadLocalPseudoRandomFunctionMessageDigest();
		int index = 0;
		for (HandshakeMessage handshakeMessage : handshakeMessages) {
			md.update(handshakeMessage.toByteArray());
			LOGGER.trace("  [{}] - {}", index, handshakeMessage.getMessageType());
			++index;
		}
		return md;
	}

	/**
	 * Clone message digest for second FINISHED message.
	 * 
	 * @param md message digest
	 * @return cloned message digest
	 * @throws HandshakeException if cloning fails.
	 * @since 3.0
	 */
	protected final MessageDigest cloneMessageDigest(MessageDigest md) throws HandshakeException {
		try {
			return (MessageDigest) md.clone();
		} catch (CloneNotSupportedException e) {
			throw new HandshakeException("Cannot create hash for second FINISHED message",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR));
		}
	}

	/**
	 * Applying the key expansion on the master secret generates a large key
	 * block to generate the encryption, MAC and IV keys. Also set the master
	 * secret to the session for later resumption handshakes.
	 * 
	 * See <a href="https://tools.ietf.org/html/rfc5246#section-6.3" target="_blank">RFC5246</a>
	 * for further details about the keys.
	 * 
	 * @param masterSecret the master secret.
	 * @see #masterSecret
	 * @see #calculateKeys(SecretKey)
	 * @since 2.3
	 */
	protected void applyMasterSecret(SecretKey masterSecret) {
		ensureUndestroyed();
		this.masterSecret = SecretUtil.create(masterSecret);
		calculateKeys(masterSecret);
		getSession().setMasterSecret(masterSecret);
	}

	/**
	 * Resume master secret from established session.
	 * 
	 * @see #masterSecret
	 * @see #calculateKeys(SecretKey)
	 * @since 3.0
	 */
	protected void resumeMasterSecret() {
		ensureUndestroyed();
		this.masterSecret = getSession().getMasterSecret();
		calculateKeys(masterSecret);
	}

	/**
	 * Calculates the encryption key, MAC key and IV from a given master secret.
	 * First, applies the key expansion to the master secret.
	 * 
	 * @param masterSecret
	 *            the master secret.
	 */
	protected void calculateKeys(SecretKey masterSecret) {
		ensureUndestroyed();
		/*
		 * Create keys as suggested in
		 * http://tools.ietf.org/html/rfc5246#section-6.3:
		 * client_write_MAC_key[SecurityParameters.mac_key_length]
		 * server_write_MAC_key[SecurityParameters.mac_key_length]
		 * client_write_key[SecurityParameters.enc_key_length]
		 * server_write_key[SecurityParameters.enc_key_length]
		 * client_write_IV[SecurityParameters.fixed_iv_length]
		 * server_write_IV[SecurityParameters.fixed_iv_length]
		 * 
		 * To protect cluster internal forwarded and backwarded messages,
		 * create two cluster key additionally with enc_key_length.
		 * 
		 * client_cluster_MAC_key[SecurityParameters.enc_key_length]
		 * server_cluster_MAC_key[SecurityParameters.enc_key_length]
		 */
		CipherSuite cipherSuite = context.getSession().getCipherSuite();
		int macKeyLength = cipherSuite.getMacKeyLength();
		int encKeyLength = cipherSuite.getEncKeyLength();
		int fixedIvLength = cipherSuite.getFixedIvLength();
		int clusterMacKeyLength = generateClusterMacKeys ? encKeyLength : 0;
		int totalLength = (macKeyLength + encKeyLength + fixedIvLength + clusterMacKeyLength) * 2;
		// See http://tools.ietf.org/html/rfc5246#section-6.3:
		//      key_block = PRF(SecurityParameters.master_secret, "key expansion",
		//                      SecurityParameters.server_random + SecurityParameters.client_random);
		byte[] seed = Bytes.concatenate(serverRandom, clientRandom);
		byte[] data = PseudoRandomFunction.doPRF(cipherSuite.getThreadLocalPseudoRandomFunctionMac(), masterSecret,
				Label.KEY_EXPANSION_LABEL, seed, totalLength);

		int index = 0;
		int length = macKeyLength;
		clientWriteMACKey = SecretUtil.create(data, index, length, "Mac");
		index += length;
		serverWriteMACKey = SecretUtil.create(data, index, length, "Mac");
		index += length;

		length = encKeyLength;
		clientWriteKey = SecretUtil.create(data, index, length, "AES");
		index += length;
		serverWriteKey = SecretUtil.create(data, index, length, "AES");
		index += length;

		length = fixedIvLength;
		clientWriteIV = SecretUtil.createIv(data, index, length);
		index += length;
		serverWriteIV = SecretUtil.createIv(data, index, length);

		if (generateClusterMacKeys) {
			length = clusterMacKeyLength;
			SecretKey clusterClientMacKey = SecretUtil.create(data, index, length, "Mac");
			index += length;
			SecretKey clusterServerMacKey = SecretUtil.create(data, index, length, "Mac");
			index += length;
			if (isClient()) {
				context.setClusterMacKeys(clusterClientMacKey, clusterServerMacKey);
			} else {
				context.setClusterMacKeys(clusterServerMacKey, clusterClientMacKey);
			}
			SecretUtil.destroy(clusterClientMacKey);
			SecretUtil.destroy(clusterServerMacKey);
		}
		Bytes.clear(data);
	}

	/**
	 * Generate seed for (extended) master secret.
	 * 
	 * @return seed
	 * @since 3.0
	 */
	protected byte[] generateMasterSecretSeed() {
		if (getSession().useExtendedMasterSecret()) {
			MessageDigest md = getSession().getCipherSuite().getThreadLocalPseudoRandomFunctionMessageDigest();
			int index = 0;
			for (HandshakeMessage handshakeMessage : handshakeMessages) {
				md.update(handshakeMessage.toByteArray());
				LOGGER.trace("  [{}] - {}", index++, handshakeMessage.getMessageType());
				if (handshakeMessage.getMessageType() == HandshakeType.CLIENT_KEY_EXCHANGE) {
					return md.digest();
				}
			}
			throw new IllegalArgumentException("client key exchange missing!");
		} else {
			return Bytes.concatenate(clientRandom, serverRandom);
		}
	}

	/**
	 * Request psk secret result for PSK cipher suites.
	 * 
	 * Sets {@link #pskRequestPending}.
	 * 
	 * @param pskIdentity PSK identity
	 * @param otherSecret others secret for ECHDE support. Maybe {@code null}.
	 * @param seed seed to be used for (extended) master secret.
	 * @throws HandshakeException if an error occurs
	 * @throws NullPointerException if seed is {@code null}
	 * @since 3.0 (added parameter seed)
	 */
	protected void requestPskSecretResult(PskPublicInformation pskIdentity, SecretKey otherSecret, byte[] seed) throws HandshakeException {
		if (seed == null) {
			throw new NullPointerException("seed must not be null!");
		}
		DTLSSession session = getSession();
		ServerNames serverNames = getServerNames();
		String hmacAlgorithm = session.getCipherSuite().getPseudoRandomFunctionMacName();
		pskRequestPending = true;
		masterSecretSeed = seed;
		this.otherSecret = SecretUtil.create(otherSecret);
		PskSecretResult result = advancedPskStore.requestPskSecretResult(connection.getConnectionId(), serverNames, pskIdentity,
				hmacAlgorithm, otherSecret, masterSecretSeed, session.useExtendedMasterSecret());
		if (result != null) {
			processPskSecretResult(result);
		}
	}

	protected final void setCurrentReadState() {
		if (isClient()) {
			context.createReadState(serverWriteKey, serverWriteIV, serverWriteMACKey);
		} else {
			context.createReadState(clientWriteKey, clientWriteIV, clientWriteMACKey);
		}
	}

	protected final void setCurrentWriteState() {
		if (isClient()) {
			context.createWriteState(clientWriteKey, clientWriteIV, clientWriteMACKey);
		} else {
			context.createWriteState(serverWriteKey, serverWriteIV, serverWriteMACKey);
		}
	}

	/**
	 * Create the FINISHED message for a pending handshake.
	 * 
	 * @param handshakeHash
	 *            the hash of the handshake messages
	 * @return create FINISHED message
	 * @since 3.0
	 */
	protected final Finished createFinishedMessage(byte[] handshakeHash) {
		if (masterSecret == null) {
			throw new IllegalStateException("master secret not available!");
		}
		return new Finished(getSession().getCipherSuite().getThreadLocalPseudoRandomFunctionMac(), masterSecret, isClient(), handshakeHash);
	}

	/**
	 * Verify the handshake hash of the FINISHED.
	 * 
	 * @param finished received FINISHED message.
	 * @param handshakeHash
	 *            the hash of the handshake messages
	 * @throws HandshakeException if the data can not be verified
	 * @since 3.0
	 */
	protected final void verifyFinished(Finished finished, byte[] handshakeHash) throws HandshakeException {
		if (masterSecret == null) {
			throw new IllegalStateException("master secret not available!");
		}
		finished.verifyData(getSession().getCipherSuite().getThreadLocalPseudoRandomFunctionMac(), masterSecret, !isClient(), handshakeHash);
	}

	/**
	 * Checks, if the master secret is available.
	 * 
	 * @return {@code true}, if available, {@code false}, otherwise.
	 * @since 3.0
	 */
	public final boolean hasMasterSecret() {
		return masterSecret != null;
	}

	/**
	 * Add a handshake message to the flight.
	 * 
	 * Assigns the handshake message sequence number.
	 * 
	 * @param flight the flight to add the messages
	 * @param handshakeMessage the handshake message
	 * @since 3.0 (replaces the wrapMessage(DTLSFlight, DTLSMessage) )
	 */
	protected final void wrapMessage(DTLSFlight flight, HandshakeMessage handshakeMessage) {
		handshakeMessage.setMessageSeq(sendMessageSequence);
		sendMessageSequence++;
		int epoch = context.getWriteEpoch();
		if (epoch == 0) {
			handshakeMessages.add(handshakeMessage);
		}
		flight.addDtlsMessage(epoch, handshakeMessage);
	}

	/**
	 * Add a change cipher specs message to the flight.
	 * 
	 * @param flight the flight to add change cipher specs wrapped messages
	 * @param ccsMessage the change cipher specs message
	 * @since 3.0 (replaces the wrapMessage(DTLSFlight, DTLSMessage) )
	 */
	protected final void wrapMessage(DTLSFlight flight, ChangeCipherSpecMessage ccsMessage) {
		flight.addDtlsMessage(context.getWriteEpoch(), ccsMessage);
	}

	/**
	 * Process a received fragmented handshake message. Checks, if all fragments
	 * are available and reassemble the handshake message, if so.
	 * 
	 * @param fragment the fragmented handshake message.
	 * @return the reassembled generic handshake message (if all fragments are
	 *         available), {@code null}, otherwise.
	 * @throws HandshakeException if the reassembling fails
	 * @since 2.4
	 */
	protected GenericHandshakeMessage reassembleFragment(FragmentedHandshakeMessage fragment)
			throws HandshakeException {

		LOGGER.debug("Processing {} message fragment ...", fragment.getMessageType());

		try {
			if (fragment.getMessageLength() > maxFragmentedHandshakeMessageLength) {
				throw new IllegalArgumentException(
						"Fragmented message length exceeded (" + fragment.getMessageLength() + " > "
								+ maxFragmentedHandshakeMessageLength + ")!");
			}
			int messageSeq = fragment.getMessageSeq();
			if (reassembledMessage == null) {
				reassembledMessage = new ReassemblingHandshakeMessage(fragment);
			} else {
				if (reassembledMessage.getMessageSeq() != messageSeq) {
					throw new IllegalArgumentException("Current reassemble message has different seqn "
							+ reassembledMessage.getMessageSeq() + " != " + messageSeq);
				}
				reassembledMessage.add(fragment);
			}
			if (reassembledMessage.isComplete()) {
				GenericHandshakeMessage message = reassembledMessage;
				LOGGER.debug("Successfully re-assembled {} message", message.getMessageType());
				reassembledMessage = null;
				return message;
			}
		} catch (IllegalArgumentException ex) {
			throw new HandshakeException(ex.getMessage(),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR));
		}

		return null;
	}

	protected abstract boolean isClient();

	/**
	 * Get handshake parameter.
	 * 
	 * @return handshake parameter.
	 * @since 3.0 (moved from DTLSSession, without obsolete conditional result)
	 */
	HandshakeParameter getParameter() {
		DTLSSession session = getSession();
		return new HandshakeParameter(session.getKeyExchange(), session.receiveCertificateType());
	}

	/**
	 * Gets the effective server names of {@link DTLSSession}.
	 * 
	 * @return the effective server names, or {@code null}, if disabled or not
	 *         available.
	 * @see #sniEnabled
	 * @since 3.0
	 */
	public final ServerNames getServerNames() {
		return sniEnabled ? getSession().getServerNames() : null;
	}

	/**
	 * Gets the session this handshaker is used to establish.
	 * 
	 * @return the session
	 */
	public final DTLSSession getSession() {
		return context.getSession();
	}

	/**
	 * Gets the dtls context this handshaker is used to establish.
	 * 
	 * @return the dtls context
	 * @since 3.0
	 */
	public final DTLSContext getDtlsContext() {
		return context;
	}

	/**
	 * Gets the IP address and port of the peer this handshaker is used to
	 * negotiate a session with.
	 * 
	 * @return the peer address
	 */
	public final InetSocketAddress getPeerAddress() {
		return connection.getPeerAddress();
	}

	/**
	 * Gets related connection.
	 * 
	 * @return connection
	 */
	public final Connection getConnection() {
		return connection;
	}

	/**
	 * Create new flight with the current {@link #getDtlsContext()} and the current
	 * {@link #flightNumber}.
	 * 
	 * @return new flight
	 * @since 2.5
	 */
	public DTLSFlight createFlight() {
		return new DTLSFlight(context, flightNumber, getPeerAddress());
	}

	/**
	 * Check, if this peer supports cid.
	 * 
	 * @return {@code true}, if the this peer supports cid, {@code false}, if
	 *         not.
	 * @see ConnectionId#supportsConnectionId(ConnectionIdGenerator)
	 * @since 3.0
	 */
	public boolean supportsConnectionId() {
		return ConnectionId.supportsConnectionId(connectionIdGenerator);
	}

	/**
	 * Get read connection ID for inbound records
	 * 
	 * @return connection ID for inbound records. {@code null}, if connection ID
	 *         is not supported, a empty connection ID, if connection ID is
	 *         supported but not used for inbound records.
	 * @since 2.5
	 */
	public ConnectionId getReadConnectionId() {
		if (ConnectionId.useConnectionId(connectionIdGenerator)) {
			// use the already created unique cid
			return connection.getConnectionId();
		} else if (ConnectionId.supportsConnectionId(connectionIdGenerator)) {
			// use empty cid
			return ConnectionId.EMPTY;
		} else {
			return null;
		}
	}

	/**
	 * Get client random.
	 * 
	 * @return client random, or {@code null}, if not available.
	 */
	public Random getClientRandom() {
		return clientRandom;
	}

	/**
	 * Get server random.
	 * 
	 * @return server random, or {@code null}, if not available.
	 */
	public Random getServerRandom() {
		return serverRandom;
	}

	/**
	 * Get the handshake message sequence number for received handshake
	 * messages.
	 * 
	 * @return handshake message sequence number
	 */
	final int getNextReceiveMessageSequenceNumber() {
		return nextReceiveMessageSequence;
	}

	/**
	 * Add outgoing application data for deferred processing.
	 * 
	 * @param outgoingMessage outgoing application data
	 */
	public void addApplicationDataForDeferredProcessing(RawData outgoingMessage) {
		if (deferredApplicationData.size() < maxDeferredProcessedOutgoingApplicationDataMessages) {
			deferredApplicationData.add(outgoingMessage);
		}
	}

	/**
	 * Add incoming records for deferred processing.
	 * 
	 * @param incomingMessage incoming record.
	 * @since 3.0 (renamed, was addRecordsForDeferredProcessing)
	 */
	public void addRecordsOfNextEpochForDeferredProcessing(Record incomingMessage) {
		addDeferredProcessedRecord(incomingMessage, nextEpochDeferredRecords);
	}

	/**
	 * Add record for deferred processing.
	 * 
	 * @param incomingMessage incoming record
	 * @param collection collection to store the record.
	 * @return {@code true}, if added, {@code false}, if
	 *         {@link #maxDeferredProcessedIncomingRecordsSize} would be
	 *         exceeded.
	 */
	private boolean addDeferredProcessedRecord(Record incomingMessage, Collection<Record> collection) {
		int size = incomingMessage.size();
		if (deferredIncomingRecordsSize + size < maxDeferredProcessedIncomingRecordsSize) {
			deferredIncomingRecordsSize += size;
			collection.add(incomingMessage);
			return true;
		} else {
			LOGGER.debug("Dropped incoming record from peer [{}], limit of {} bytes exceeded by {}+{} bytes!",
					incomingMessage.getPeerAddress(), maxDeferredProcessedIncomingRecordsSize, deferredIncomingRecordsSize, size);
			recordLayer.dropReceivedRecord(incomingMessage);
			return false;
		}
	}

	/**
	 * Remove record from deferred processing.
	 * 
	 * @param incomingMessage incoming record to remove
	 * @param collection collection to remove the record
	 */
	private void removeDeferredProcessedRecord(Record incomingMessage, Collection<Record> collection) {
		if (collection.remove(incomingMessage)) {
			int size = incomingMessage.size();
			if (deferredIncomingRecordsSize < size) {
				LOGGER.warn(
						"deferred processed incoming records corrupted for peer [{}]! Removing {} bytes exceeds available {} bytes!",
						incomingMessage.getPeerAddress(), size, deferredIncomingRecordsSize);
				throw new IllegalArgumentException("deferred processing of incoming records corrupted!");
			}
			deferredIncomingRecordsSize -= size;
		}
	}

	/**
	 * Take deferred outgoing application data.
	 * 
	 * @return list of application data
	 */
	public List<RawData> takeDeferredApplicationData() {
		List<RawData> applicationData = new ArrayList<RawData>(deferredApplicationData);
		deferredApplicationData.clear();
		return applicationData;
	}

	/**
	 * Take deferred incoming records of next epoch.
	 * 
	 * @return list if deferred incoming records
	 */
	public List<Record> takeDeferredRecordsOfNextEpoch() {
		List<Record> records = new ArrayList<Record>(nextEpochDeferredRecords);
		for (Record record : records) {
			removeDeferredProcessedRecord(record, nextEpochDeferredRecords);
		}
		if (!nextEpochDeferredRecords.isEmpty()) {
			LOGGER.warn("{} left deferred records", nextEpochDeferredRecords.size());
			nextEpochDeferredRecords.clear();
		}
		return records;
	}

	/**
	 * Take deferred outgoing application data from provided handshaker.
	 * 
	 * @param replacedHandshaker replaced handshaker to take deferred outgoing
	 *            application data
	 */
	public void takeDeferredApplicationData(Handshaker replacedHandshaker) {
		deferredApplicationData.addAll(replacedHandshaker.takeDeferredApplicationData());
	}

	/**
	 * Registers an outbound flight that has not been acknowledged by the peer
	 * yet in order to be able to cancel its re-transmission later once it has
	 * been acknowledged. The retransmission of a different previous pending
	 * flight will be cancelled also.
	 */
	public void completePendingFlight() {
		this.retransmitFlight = null;
		DTLSFlight flight = this.pendingFlight.get();
		if (flight != null) {
			flight.setResponseCompleted();
		}
	}

	/**
	 * Send last flight.
	 * 
	 * The last flight doesn't need retransmission.
	 * 
	 * @param flight last flight to send
	 * @see #sendFlight(DTLSFlight)
	 */
	public void sendLastFlight(DTLSFlight flight) {
		timeoutLastFlight = timer.schedule(new TimeoutCompletedTask(), nanosExpireTimeout, TimeUnit.NANOSECONDS);
		flight.setRetransmissionNeeded(false);
		sendFlight(flight);
	}

	/**
	 * Send flight.
	 * 
	 * @param flight flight to send
	 * @see #sendFlight(DTLSFlight)
	 */
	public void sendFlight(DTLSFlight flight) {
		completePendingFlight();
		try {
			int timeout = retransmissionTimeout;
			float noise = retransmissionRandomFactor - 1.0F;
			if (noise > 0.0) {
				timeout += RandomManager.currentRandom().nextInt(Math.round(timeout * noise));
			}
			if (eccExpected) {
				timeout += additionalTimeoutForEcc;
				eccExpected = false;
			}
			timeout = Math.min(timeout, maxRetransmissionTimeout);
			flight.setTimeout(timeout);
			flightSendNanos = ClockUtil.nanoRealtime();
			nanosExpireTime = nanosExpireTimeout + flightSendNanos;
			int maxDatagramSize = recordLayer.getMaxDatagramSize(ipv6);
			int maxFragmentSize = getSession().getEffectiveFragmentLimit();
			List<DatagramPacket> datagrams = flight.getDatagrams(maxDatagramSize, maxFragmentSize,
					useMultiHandshakeMessagesRecord, useMultiRecordMessages, false);
			LOGGER.trace(
					"Sending flight of {} message(s) to peer [{}] using {} datagram(s) of max. {} bytes and {} ms timeout.",
					flight.getNumberOfMessages(), peerToLog, datagrams.size(), maxDatagramSize, timeout);
			recordLayer.sendFlight(datagrams);
			pendingFlight.set(flight);
			if (flight.isRetransmissionNeeded()) {
				retransmitFlight = new TimeoutPeerTask(flight);
				flight.scheduleRetransmission(timer, retransmitFlight);
			}
			int effectiveMessageSize = flight.getEffectiveMaxMessageSize();
			if (effectiveMessageSize > 0) {
				context.setEffectiveMaxMessageSize(effectiveMessageSize);
			}
		} catch (HandshakeException e) {
			handshakeFailed(new Exception("handshake flight " + flight.getFlightNumber() + " failed!", e));
		} catch (IOException e) {
			handshakeFailed(new Exception("handshake flight " + flight.getFlightNumber() + " failed!", e));
		}
	}

	/**
	 * Handle flight timeout.
	 * 
	 * @param flight affected flight
	 * @since 2.4
	 */
	private void handleTimeout(DTLSFlight flight) {

		if (!flight.isResponseCompleted()) {
			Handshaker handshaker = connection.getOngoingHandshake();
			if (null != handshaker) {
				if (!handshaker.isProbing() && connection.hasEstablishedDtlsContext()) {
					return;
				}
				Exception cause = null;
				String message = "";
				boolean timeout = false;
				if (!connection.isExecuting() || !recordLayer.isRunning()) {
					message = " Stopped by shutdown!";
				} else {
					// set DTLS retransmission maximum
					int tries = flight.getTries();
					if (tries < maxRetransmissions && handshaker.isExpired()) {
						// limit of retransmissions not reached
						// but handshake expired during Android / OS "deep sleep"
						message = " Stopped by expired realtime!";
						timeout = true;
					} else if (tries < maxRetransmissions) {
						// limit of retransmissions not reached
						if (useEarlyStopRetransmission && flight.isResponseStarted()) {
							// don't retransmit, just schedule last timeout
							while (tries < maxRetransmissions) {
								++tries;
								flight.incrementTries();
								flight.incrementTimeout(retransmissionTimeoutScale, maxRetransmissionTimeout);
							}
							// increment one more to indicate, that
							// handshake times out without reaching
							// the max retransmissions.
							flight.incrementTries();
							LOGGER.trace("schedule handshake timeout {}ms after flight {}", flight.getTimeout(),
									flight.getFlightNumber());
							Runnable retransmit = retransmitFlight;
							if (retransmit != null) {
								flight.scheduleRetransmission(timer, retransmit);
							}
							return;
						}

						LOGGER.trace("Re-transmitting flight for [{}], [{}] retransmissions left",
								peerToLog, maxRetransmissions - tries - 1);
						try {
							flight.incrementTries();
							flight.incrementTimeout(retransmissionTimeoutScale, maxRetransmissionTimeout);
							int maxDatagramSize = recordLayer.getMaxDatagramSize(ipv6);
							int maxFragmentSize = getSession().getEffectiveFragmentLimit();
							boolean backOff = backOffRetransmission > 0 && (tries + 1) > backOffRetransmission;
							List<DatagramPacket> datagrams = flight.getDatagrams(maxDatagramSize, maxFragmentSize,
									useMultiHandshakeMessagesRecord, useMultiRecordMessages, backOff);
							LOGGER.debug(
									"Resending flight {} of {} message(s) to peer [{}] using {} datagram(s) of max. {} bytes. Retransmission {} of {}.",
									flight.getFlightNumber(), flight.getNumberOfMessages(), peerToLog, datagrams.size(),
									maxDatagramSize, tries + 1, maxRetransmissions);
							recordLayer.sendFlight(datagrams);

							// schedule next retransmission
							Runnable retransmit = retransmitFlight;
							if (retransmit != null) {
								flight.scheduleRetransmission(timer, retransmit);
							}
							handshaker.handshakeFlightRetransmitted(flight.getFlightNumber());
							return;
						} catch (IOException e) {
							// stop retransmission on IOExceptions
							cause = e;
							message = " " + e.getMessage();
							LOGGER.warn("Cannot retransmit flight to peer [{}]", peerToLog, e);
						} catch (HandshakeException e) {
							LOGGER.warn("Cannot retransmit flight to peer [{}]", peerToLog, e);
							cause = e;
							message = " " + e.getMessage();
						}
					} else if (tries > maxRetransmissions) {
						LOGGER.debug("Flight for [{}] has reached timeout, discarding ...", peerToLog);
						message = " Stopped by timeout!";
						timeout = true;
					} else {
						LOGGER.debug(
								"Flight for [{}] has reached maximum no. [{}] of retransmissions, discarding ...",
								peerToLog, maxRetransmissions);
						message = " Stopped by timeout after " + maxRetransmissions + " retransmissions!";
						timeout = true;
					}
				}
				LOGGER.debug("Flight {} of {} message(s) to peer [{}] failed,{} Retransmission {} of {}.",
						flight.getFlightNumber(), flight.getNumberOfMessages(), peerToLog, message, flight.getTries(),
						maxRetransmissions);
				if (hasPendingApiCall()) {
					cause = new HandshakeException("Internal callback timeout!",
							new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR));
				}
				if (cause instanceof HandshakeException) {
					recordLayer.processHandshakeException(connection, (HandshakeException) cause);
					return;
				}
				// inform handshaker
				if (timeout) {
					handshaker.handshakeFailed(new DtlsHandshakeTimeoutException(
							"Handshake flight " + flight.getFlightNumber() + " failed!" + message,
							flight.getFlightNumber()));
				} else {
					handshaker.handshakeFailed(new DtlsException(
							"Handshake flight " + flight.getFlightNumber() + " failed!" + message, cause));
				}
			}
		}
	}

	/**
	 * Peer related task for executing in serial executor.
	 * 
	 * @since 2.4
	 */
	private class ConnectionTask implements Runnable {
		/**
		 * Task to execute in serial executor.
		 */
		private final Runnable task;
		/**
		 * Flag to force execution, if serial execution is exhausted or
		 * shutdown. The task is then executed in the context of this
		 * {@link Runnable}.
		 */
		private final boolean force;
		/**
		 * Create peer task.
		 * 
		 * @param task task to be execute in serial executor
		 * @param force flag indicating, that the task should be executed, even
		 *            if the serial executors are exhausted or shutdown.
		 */
		private ConnectionTask(Runnable task, boolean force) {
			this.task = task;
			this.force = force;
		}

		@Override
		public void run() {
			final SerialExecutor serialExecutor = connection.getExecutor();
			try {
				serialExecutor.execute(task);
			} catch (RejectedExecutionException e) {
				LOGGER.debug("Execution rejected while execute task of peer: {}", connection.getPeerAddress(), e);
				if (force) {
					task.run();
				}
			}
		}
	}

	/**
	 * Peer task calling the {@link #handleTimeout(DTLSFlight)}.
	 * 
	 * @since 2.4
	 */
	private class TimeoutPeerTask extends ConnectionTask {

		private TimeoutPeerTask(final DTLSFlight flight) {
			super(new Runnable() {
				@Override
				public void run() {
					handleTimeout(flight);
				}
			}, true);
		}
	}

	private class TimeoutCompletedTask extends ConnectionTask {

		private TimeoutCompletedTask() {
			super(new Runnable() {
				@Override
				public void run() {
					if (recordLayer.isRunning()) {
						handshakeCompleted();
					}
				}
			}, false);
		}
	}

	/**
	 * Adds a listener to the list of listeners to be notified
	 * about session life cycle events.
	 * 
	 * @param listener The listener to add.
	 */
	public final void addSessionListener(SessionListener listener) {
		if (listener != null) {
			sessionListeners.add(listener);
		}
	}

	/**
	 * Removes a listener from the list of listeners to be notified
	 * about session life cycle events.
	 * 
	 * @param listener The listener to remove.
	 */
	public final void removeSessionListener(SessionListener listener) {
		if (listener != null) {
			sessionListeners.remove(listener);
		}
	}

	/**
	 * Forward handshake start to registered listeners.
	 * 
	 * @throws HandshakeException if thrown by listener
	 */
	protected final void handshakeStarted() throws HandshakeException {
		LOGGER.debug("handshake started {}", connection);
		for (SessionListener sessionListener : sessionListeners) {
			sessionListener.handshakeStarted(this);
		}
	}

	/**
	 * Forward session established to registered listeners.
	 * 
	 * {@link #amendPeerPrincipal()}.
	 * 
	 * @throws HandshakeException if thrown by listener
	 */
	protected final void contextEstablished() throws HandshakeException {
		if (!contextEstablished) {
			if (context.getWriteState().hasValidCipherSuite()) {
				LOGGER.debug("dtls context established {}", connection);
				amendPeerPrincipal();
				contextEstablished = true;
				for (SessionListener sessionListener : sessionListeners) {
					sessionListener.contextEstablished(this, context);
				}
			} else {
				handshakeFailed(
						new DtlsException("Failed establishing a incomplete session."));
			}
		}
	}

	/**
	 * Forward handshake completed to registered listeners.
	 */
	public final void handshakeCompleted() {
		if (!handshakeCompleted) {
			if (timeoutLastFlight != null) {
				timeoutLastFlight.cancel(false);
			}
			handshakeCompleted = true;
			completePendingFlight();
			for (SessionListener sessionListener : sessionListeners) {
				sessionListener.handshakeCompleted(this);
			}
			SecretUtil.destroy(this);
			LOGGER.debug("handshake completed {}", connection);
		}
	}

	/**
	 * Notifies all registered session listeners about a handshake failure.
	 * 
	 * Listeners are intended to remove the connection, if no session is
	 * established.
	 * 
	 * If {@link #setFailureCause(Throwable)} was called before, only calls with
	 * the same cause will notify the listeners. If
	 * {@link #setFailureCause(Throwable)} wasn't called before, sets the
	 * <em>cause</em> property to the given cause.
	 * 
	 * @param cause The reason for the failure.
	 * @see #isRemovingConnection()
	 * @see #handshakeAborted(Throwable)
	 */
	public final void handshakeFailed(Throwable cause) {
		if (this.cause == null) {
			this.cause = cause;
		}
		if (!handshakeFailed && this.cause == cause) {
			LOGGER.debug("handshake failed {}", connection, cause);
			handshakeFailed = true;
			completePendingFlight();
			for (SessionListener sessionListener : sessionListeners) {
				sessionListener.handshakeFailed(this, cause);
			}
			SecretUtil.destroy(context);
			SecretUtil.destroy(this);
		}
	}

	/**
	 * Abort handshake.
	 * 
	 * Notifies all registered session listeners about a handshake failure.
	 * Listeners are intended to keep the connection.
	 * 
	 * If {@link #setFailureCause(Throwable)} was called before, only calls with
	 * the same cause will notify the listeners. If
	 * {@link #setFailureCause(Throwable)} wasn't called before, sets the
	 * <em>cause</em> property to the given cause.
	 * 
	 * @param cause The reason for the abort.
	 * @see #handshakeFailed(Throwable)
	 * @see #isRemovingConnection()
	 * @since 2.1
	 */
	public final void handshakeAborted(Throwable cause) {
		this.handshakeAborted = true;
		handshakeFailed(cause);
	}

	/**
	 * Checks, if the dtls context is established.
	 * 
	 * Indicates, that the peer has send it's FINISH and is awaiting to receive
	 * data or alerts in epoch 1.
	 * 
	 * @return {@code true}, if the dtls context is established, {@code false},
	 *         otherwise.
	 * @since 3.0
	 */
	public boolean hasContextEstablished() {
		return contextEstablished;
	}

	/**
	 * Test, if handshake was started in probing mode.
	 * 
	 * Usually a resuming client handshake removes the DTLS context from the
	 * connection store with the start. Probing removes DTLS context only with
	 * the first data received back. If the handshake expires before some data
	 * is received back, the original DTLS context is used again.
	 * 
	 * @return {@code true}, if handshake is in probing mode, {@code false},
	 *         otherwise.
	 * @see ResumingClientHandshaker
	 * @see ClientHandshaker
	 * @since 2.1
	 */
	public boolean isProbing() {
		// intended to be overridden by the ResumingClientHandshaker
		return false;
	}

	/**
	 * Reset probing mode, when data is received during.
	 * 
	 * @see ResumingClientHandshaker
	 * @since 2.1
	 */
	public void resetProbing() {
		// intended to be overriden by the ResumingClientHandshaker
	}

	/**
	 * Test, if handshake is expired according nano realtime.
	 * 
	 * Used to mitigate deep sleep during handshakes.
	 * 
	 * @return {@code true}, if handshake is expired, mainly during deep sleep,
	 *         {@code false}, if the handshake is still in time.
	 * @since 2.1
	 */
	public boolean isExpired() {
		return !contextEstablished && pendingFlight.get() != null && (ClockUtil.nanoRealtime() -nanosExpireTime) > 0;
	}

	/**
	 * Check, if psk request is pending.
	 * 
	 * @return {@code true}, if psk request is pending, {@code false},
	 *         otherwise.
	 */
	public boolean isPskRequestPending() {
		return pskRequestPending;
	}

	/**
	 * Check, if the connection must be removed.
	 * 
	 * The connection must be removed, if {@link #handshakeFailed(Throwable)}
	 * was called, and the connection has no established session.
	 * 
	 * @return {@code true}, remove the connection, {@code false}, keep it.
	 * @since 2.1
	 */
	public boolean isRemovingConnection() {
		return !handshakeAborted && !connection.hasEstablishedDtlsContext();
	}

	/**
	 * Get cause of failure.
	 * 
	 * @return cause of failure, or {@code null}, if the cause is unknown and not set before
	 * @see #setFailureCause(Throwable)
	 * @see #handshakeFailed(Throwable)
	 */
	public Throwable getFailureCause() {
		return cause;
	}

	/**
	 * Set the failure cause.
	 * 
	 * In some cases the cleanup of the handshake may consider a different
	 * failure as cause. This prevents {@link #handshakeFailed(Throwable)} to
	 * notify listener in that case.
	 * 
	 * @param cause failure cause
	 * @see #handshakeFailed(Throwable)
	 * @see #getFailureCause()
	 */
	public void setFailureCause(Throwable cause) {
		completePendingFlight();
		this.cause = cause;
	}

	/**
	 * Enable to generate keys for cluster MAC.
	 * 
	 * @param enable {@code true}, generate keys for cluster MAC, {@code false},
	 *            otherwise.
	 * @since 2.5
	 */
	public void setGenerateClusterMacKeys(boolean enable) {
		generateClusterMacKeys = enable;
	}

	/**
	 * Notifies all registered session listeners about a handshake
	 * retransmit of a flight.
	 * 
	 * @param flight number of retransmitted flight.
	 */
	public final void handshakeFlightRetransmitted(int flight) {
		for (SessionListener sessionListener : sessionListeners) {
			sessionListener.handshakeFlightRetransmitted(this, flight);
		}
		for (RawData message : deferredApplicationData) {
			message.onDtlsRetransmission(flight);
		}
	}

	/**
	 * Checks whether the peer's <em>CHANGE_CIPHER_SPEC</em> message is the next message
	 * expected in the ongoing handshake.
	 * 
	 * @return {@code true} if the message is expected next.
	 */
	public final boolean isChangeCipherSpecMessageExpected() {
		return changeCipherSuiteMessageExpected;
	}

	/**
	 * Marks this handshaker to expect the peer's <em>CHANGE_CIPHER_SPEC</em> message next.
	 */
	protected final void expectChangeCipherSpecMessage() {
		this.changeCipherSuiteMessageExpected = true;
	}

	/**
	 * Marks this handshaker to expect the peer to calculate some ECC function.
	 * {@link #additionalTimeoutForEcc} will be added for the next flight in
	 * that case.
	 * 
	 * @since 3.0
	 */
	protected void expectEcc() {
		this.eccExpected = true;
	}

	/**
	 * Start validating the X.509 certificate chain provided by the the peer as
	 * part of this message, or the raw public key of the message.
	 *
	 * This method delegates both certificate validation to the
	 * {@link NewAdvancedCertificateVerifier}. If a asynchronous implementation
	 * of {@link NewAdvancedCertificateVerifier} is used, the result will be not
	 * available after this call, but will be available after the callback of
	 * the asynchronous implementation.
	 *
	 * @param message the certificate message
	 * @param verifySubject {@code true} to verify the certificate's subject,
	 *            {@code false}, if not.
	 *
	 * @throws HandshakeException if any of the checks fails
	 * @see DtlsConfig#DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT
	 * @since 3.0 (added parameter verifySubject)
	 */
	public void verifyCertificate(CertificateMessage message, boolean verifySubject) throws HandshakeException {
		if (certificateVerifier == null) {
			LOGGER.debug("Certificate validation failed: no verifier available!");
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE);
			throw new HandshakeException("Trust is not possible!", alert);
		}
		LOGGER.info("Start certificate verification.");
		certificateVerificationPending = true;
		this.otherPeersPublicKey = message.getPublicKey();

		CertificateVerificationResult verificationResult = certificateVerifier.verifyCertificate(
				connection.getConnectionId(), getServerNames(), getPeerAddress(), !isClient(),
				verifySubject, useTruncatedCertificatePathForVerification, message);
		if (verificationResult != null) {
			processCertificateVerificationResult(verificationResult);
		}
	}

	/**
	 * Request the certificate based identity.
	 * 
	 * @param issuers list of trusted issuers. May be {@code null} or empty.
	 * @param serverNames indicated server names. May be {@code null} or empty.
	 * @param certificateKeyAlgorithms list of certificate key algorithms to
	 *            select a node's certificate. May be {@code null} or empty.
	 * @param signatureAndHashAlgorithms list of supported signatures and hash
	 *            algorithms. May be {@code null} or empty.
	 * @param curves ec-curves (supported groups). May be {@code null} or empty.
	 * @return {@code true}, if the certificate based identity is available,
	 *         {@code false}, if the certificate based identity is requested.
	 * @throws HandshakeException if any of the checks fails
	 * @see CertificateProvider#requestCertificateIdentity(ConnectionId,
	 *      boolean, List, ServerNames, List, List, List)
	 * @since 3.0
	 */
	public boolean requestCertificateIdentity(List<X500Principal> issuers, ServerNames serverNames,
			List<CertificateKeyAlgorithm> certificateKeyAlgorithms, List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms,
			List<SupportedGroup> curves) throws HandshakeException {
		certificateIdentityPending = true;
		CertificateIdentityResult result;
		if (certificateIdentityProvider == null) {
			result = new CertificateIdentityResult(connection.getConnectionId(), null);
		} else {
			LOGGER.info("Start certificate identity.");
			result = certificateIdentityProvider.requestCertificateIdentity(connection.getConnectionId(), isClient(),
					issuers, serverNames, certificateKeyAlgorithms, signatureAndHashAlgorithms, curves);
		}
		if (result != null) {
			processCertificateIdentityResult(result);
			return false;
		} else {
			return true;
		}
	}

	@Override
	public void destroy() throws DestroyFailedException {
		SecretUtil.destroy(otherSecret);
		otherSecret = null;
		SecretUtil.destroy(masterSecret);
		masterSecret = null;
		SecretUtil.destroy(clientWriteKey);
		clientWriteKey = null;
		SecretUtil.destroy(clientWriteMACKey);
		clientWriteMACKey = null;
		SecretUtil.destroy(clientWriteIV);
		clientWriteIV = null;
		SecretUtil.destroy(serverWriteKey);
		serverWriteKey = null;
		SecretUtil.destroy(serverWriteMACKey);
		serverWriteMACKey = null;
		SecretUtil.destroy(serverWriteIV);
		serverWriteIV = null;
		destroyed = true;
	}

	@Override
	public boolean isDestroyed() {
		return destroyed;
	}

	/**
	 * Check, if this handshaker has been destroyed.
	 * 
	 * @throws IllegalStateException if the handshake has been destroyed.
	 */
	protected void ensureUndestroyed() {
		if (destroyed) {
			if (handshakeFailed) {
				throw new IllegalStateException("secrets destroyed after failure!", cause);
			} else if (contextEstablished) {
				throw new IllegalStateException("secrets destroyed after success!");
			} else {
				throw new IllegalStateException("secrets destroyed ???");
			}
		}
	}

	/**
	 * Amends the peer principal with additional application level information.
	 */
	private void amendPeerPrincipal() {

		DTLSSession session = getSession();
		Principal peerIdentity = session.getPeerIdentity();
		if (peerIdentity instanceof ExtensiblePrincipal) {
			// amend the client principal with additional application level information
			@SuppressWarnings("unchecked")
			ExtensiblePrincipal<? extends Principal> extensibleClientIdentity = (ExtensiblePrincipal<? extends Principal>) peerIdentity;
			AdditionalInfo additionalInfo = getAdditionalPeerInfo(peerIdentity);
			if (additionalInfo != null) {
				session.setPeerIdentity(extensibleClientIdentity.amend(additionalInfo));
			}
		}
	}

	private AdditionalInfo getAdditionalPeerInfo(Principal peerIdentity) {
		if (applicationLevelInfoSupplier == null || peerIdentity == null) {
			return null;
		} else {
			return applicationLevelInfoSupplier.getInfo(peerIdentity, customArgument);
		}
	}
}
