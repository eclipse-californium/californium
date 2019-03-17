/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction.Label;
import org.eclipse.californium.scandium.dtls.rpkstore.TrustedRpkStore;
import org.eclipse.californium.scandium.dtls.x509.CertificateVerifier;
import org.eclipse.californium.scandium.util.ByteArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A base class for the DTLS handshake protocol.
 * 
 * Contains all functionality and fields needed by all types of handshakers.
 */
public abstract class Handshaker {

	private final Logger LOGGER = LoggerFactory.getLogger(getClass().getName());

	/**
	 * Indicates whether this handshaker performs the client or server part of
	 * the protocol.
	 */
	protected final boolean isClient;

	protected int state = -1;

	protected ProtocolVersion usedProtocol;
	protected Random clientRandom;
	protected Random serverRandom;

	/** The helper class to execute the ECDHE key agreement and key generation. */
	protected ECDHECryptography ecdhe;

	private SecretKey clientWriteMACKey;
	private SecretKey serverWriteMACKey;

	private IvParameterSpec clientWriteIV;
	private IvParameterSpec serverWriteIV;

	private SecretKey clientWriteKey;
	private SecretKey serverWriteKey;

	protected final DTLSSession session;
	/**
	 * The logic in charge of verifying the chain of certificates asserting this
	 * handshaker's identity
	 */
	protected final CertificateVerifier certificateVerifier;

	/** The trusted raw public keys */
	protected final TrustedRpkStore rpkStore;

	/**
	 * The configured connection id length. {@code null}, not supported,
	 * {@code 0} supported but not used.
	 */
	protected final ConnectionIdGenerator connectionIdGenerator;

	/**
	 * The current sequence number (in the handshake message called message_seq)
	 * for this handshake.
	 */
	private int sequenceNumber = 0;

	/** The next expected handshake message sequence number. */
	private int nextReceiveSeq = 0;

	/** The current flight number. */
	protected int flightNumber = 0;

	/** Maximum length of reassembled fragmented handshake messages */
	private final int maxFragmentedHandshakeMessageLength;
	/** Maximum number of application data messages, which may be processed deferred after the handshake */
	private final int maxDeferredProcessedApplicationDataMessages;
	/** List of application data messages, which are send deferred after the handshake */
	private final  List<RawData> deferredApplicationData;
	/** List of received application data messages, which are processed deferred after the handshake */
	private final  List<Record> deferredRecords;
	/** Currently pending flight */
	private final AtomicReference<DTLSFlight> pendingFlight = new AtomicReference<DTLSFlight>();

	private final RecordLayer recordLayer;
	/**
	 * Associated connection for this handshaker.
	 */
	private final Connection connection;

	/** Buffer for received records that can not be processed immediately. */
	protected InboundMessageBuffer inboundMessageBuffer;

	/**
	 * Store for partial to reassembled handshake messages.
	 */
	protected Map<Integer, ReassemblingHandshakeMessage> reassembledMessages = new HashMap<Integer, ReassemblingHandshakeMessage>();

	/**
	 * The message digest to compute the handshake hashes sent in the
	 * {@link Finished} messages.
	 */
	protected MessageDigest md;

	/** All the handshake messages exchanged before the CertificateVerify message. */
	protected byte[] handshakeMessages = Bytes.EMPTY;

	/** The handshaker's private key. */
	protected PrivateKey privateKey;

	/** The handshaker's public key. */
	protected PublicKey publicKey;

	/** The chain of certificates asserting this handshaker's identity */
	protected List<X509Certificate> certificateChain;

	/**
	 * Support Server Name Indication TLS extension.
	 */
	protected boolean sniEnabled = true;

	private final Set<SessionListener> sessionListeners = new LinkedHashSet<>();

	private boolean changeCipherSuiteMessageExpected = false;
	private boolean sessionEstablished = false;
	private boolean handshakeFailed = false;

	// Constructor ////////////////////////////////////////////////////

	/**
	 * Creates a new handshaker for negotiating a DTLS session with a given
	 * peer.
	 * 
	 * @param isClient indicates whether this handshaker plays the client or
	 *            server role.
	 * @param initialMessageSeq the initial message sequence number to use and
	 *            expect in the exchange of handshake messages with the peer.
	 *            This parameter can be used to initialize the
	 *            <em>message_seq</em> and <em>receive_next_seq</em> counters to
	 *            a value larger than 0, e.g. if one or more cookie exchange
	 *            round-trips have been performed with the peer before the
	 *            handshake starts.
	 * @param session the session this handshaker is negotiating.
	 * @param recordLayer the object to use for sending flights to the peer.
	 * @param connection the connection related to this handshaker.
	 * @param config the dtls configuration
	 * @param maxTransmissionUnit the MTU value reported by the network
	 *            interface the record layer is bound to.
	 * @throws NullPointerException if session, recordLayer, or config is
	 *             <code>null</code>.
	 * @throws IllegalArgumentException if the initial message sequence number
	 *             is negative
	 */
	protected Handshaker(boolean isClient, int initialMessageSeq, DTLSSession session, RecordLayer recordLayer,
			Connection connection, DtlsConnectorConfig config, int maxTransmissionUnit) {
		if (session == null) {
			throw new NullPointerException("DTLS Session must not be null");
		} else if (recordLayer == null) {
			throw new NullPointerException("Record layer must not be null");
		} else if (config == null) {
			throw new NullPointerException("Dtls Connector Config must not be null");
		} else if (initialMessageSeq < 0) {
			throw new IllegalArgumentException("Initial message sequence number must not be negative");
		}
		this.isClient = isClient;
		this.sequenceNumber = initialMessageSeq;
		this.nextReceiveSeq = initialMessageSeq;
		this.session = session;
		this.recordLayer = recordLayer;
		this.connection = connection;
		this.connectionIdGenerator = config.getConnectionIdGenerator();
		this.maxFragmentedHandshakeMessageLength = config.getMaxFragmentedHandshakeMessageLength();
		this.maxDeferredProcessedApplicationDataMessages = config.getMaxDeferredProcessedApplicationDataMessages();
		this.deferredApplicationData = new ArrayList<RawData>(maxDeferredProcessedApplicationDataMessages);
		this.deferredRecords = new ArrayList<Record>(maxDeferredProcessedApplicationDataMessages);
		if (connection != null) {
			addSessionListener(connection.getSessionListener());
		}
		this.certificateVerifier = config.getCertificateVerifier();
		this.session.setMaxTransmissionUnit(maxTransmissionUnit);
		this.inboundMessageBuffer = new InboundMessageBuffer();

		this.rpkStore = config.getRpkTrustStore();
	}

	/**
	 * A queue for buffering inbound handshake messages.
	 */
	class InboundMessageBuffer {

		private ChangeCipherSpecMessage changeCipherSpec = null;

		private SortedSet<Record> queue = new TreeSet<>(new Comparator<Record>() {

			@Override
			public int compare(Record r1, Record r2) {

				if (r1.getEpoch() < r2.getEpoch()) {
					return -1;
				} else if (r1.getEpoch() > r2.getEpoch()) {
					return 1;
				} else if (r1.getSequenceNumber() < r2.getSequenceNumber()) {
					return -1;
				} else if (r1.getSequenceNumber() > r2.getSequenceNumber()) {
					return 1;
				} else {
					return 0;
				}
			}
		});

		boolean isEmpty() {
			return queue.isEmpty();
		}

		/**
		 * Gets (and removes from the queue) the handshake message
		 * with this handshake's next expected message sequence number.
		 * 
		 * @return the message or <code>null</code> if the queue does not contain the next expected
		 *           message (yet) 
		 * @throws HandshakeException if the record's plaintext fragment could not be parsed
		 *           into a handshake message
		 * @throws GeneralSecurityException if the record's ciphertext fragment could not be decrypted 
		 */
		DTLSMessage getNextMessage() throws GeneralSecurityException, HandshakeException {

			DTLSMessage result = null;

			if (isChangeCipherSpecMessageExpected() && changeCipherSpec != null) {
				result = changeCipherSpec;
				changeCipherSpec = null;
			} else {

				for (Record record : queue) {
					if (record.getEpoch() == session.getReadEpoch()) {
						HandshakeMessage msg = (HandshakeMessage) record.getFragment(session.getReadState());
						if (msg.getMessageSeq() == nextReceiveSeq) {
							result = msg;
							queue.remove(record);
							break;
						}
					}
				}
			}

			return result;
		}

		/**
		 * Checks if a given record contains a message that can be processed immediately as part
		 * of the ongoing handshake.
		 * <p>
		 * This is the case if the record is from the <em>current read epoch</em> and the contained
		 * message is either a <em>CHANGE_CIPHER_SPEC</em> message or a <em>HANDSHAKE</em> message
		 * with the next expected sequence number.
		 * <p>
		 * If the record contains a message from a future epoch or having a sequence number that is
		 * not the next expected one, the record is put into a buffer for later processing when all
		 * fragments are available and/or the message's sequence number becomes the next expected one.
		 * 
		 * @param record the record containing the message to check
		 * @return the contained message if the message is up for immediate processing or <code>null</code>
		 *         if the message cannot be processed immediately
		 * @throws HandshakeException if the record's plaintext fragment could not be parsed
		 *           into a message
		 * @throws GeneralSecurityException if the record's ciphertext fragment could not be de-crypted 
		 */
		DTLSMessage getNextMessage(Record candidate) throws GeneralSecurityException, HandshakeException {
			int epoch = candidate.getEpoch();
			if (epoch < session.getReadEpoch()) {
				// discard old message
				LOGGER.debug("Discarding message from peer [{}] from past epoch [{}] < current epoch [{}]",
						getPeerAddress(), epoch, session.getReadEpoch());
				return null;
			} else if (epoch == session.getReadEpoch()) {
				DTLSMessage fragment = candidate.getFragment();
				switch (fragment.getContentType()) {
				case ALERT:
					return fragment;
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
						return fragment;
					} else {
						// store message for later processing
						LOGGER.debug("Change Cipher Spec is not expected and therefore kept for later processing!");
						changeCipherSpec = (ChangeCipherSpecMessage) fragment;
						return null;
					}
				case HANDSHAKE:
					HandshakeMessage handshakeMessage = (HandshakeMessage) fragment;
					int messageSeq = handshakeMessage.getMessageSeq();
					if (messageSeq == nextReceiveSeq) {
						return handshakeMessage;
					} else if (messageSeq > nextReceiveSeq) {
						LOGGER.debug(
								"Queued newer message from current epoch, message_seq [{}] > next_receive_seq [{}]",
								messageSeq, nextReceiveSeq);
						queue.add(candidate);
						return null;
					} else {
						LOGGER.debug("Discarding old message, message_seq [{}] < next_receive_seq [{}]", messageSeq,
								nextReceiveSeq);
						return null;
					}
				default:
					LOGGER.debug("Cannot process message of type [{}], discarding...", fragment.getContentType());
					return null;
				}
			} else {
				// newer epoch, queue message
				queue.add(candidate);
				LOGGER.debug("Queueing HANDSHAKE message from future epoch [{}] > current epoch [{}]", epoch,
						getSession().getReadEpoch());
				return null;
			}
		}
	}

	/**
	 * Processes a handshake record received from a peer based on the
	 * handshake's current state.
	 * 
	 * This method only does a duplicate check as described in
	 * <a href="http://tools.ietf.org/html/rfc6347#section-4.1.2.6">
     * section 4.1.2.6 of the DTLS 1.2 spec</a> and then delegates
     * processing of the record to the {@link #doProcessMessage(DTLSMessage)}
     * method.
     * 
	 * @param record
	 *            the handshake record
	 * @throws HandshakeException if the record's plaintext fragment cannot be parsed into
	 *            a handshake message or cannot be processed properly
	 */
	public final void processMessage(Record record) throws HandshakeException {
		// The DTLS 1.2 spec (section 4.1.2.6) advises to do replay detection
		// before MAC validation based on the record's sequence numbers
		// see http://tools.ietf.org/html/rfc6347#section-4.1.2.6
		boolean sameEpoch = session.getReadEpoch() == record.getEpoch();
		if ((sameEpoch && !session.isDuplicate(record.getSequenceNumber()))
				|| (session.getReadEpoch() + 1) == record.getEpoch()) {
			try {
				record.setSession(session);
				DTLSMessage messageToProcess = inboundMessageBuffer.getNextMessage(record);
				while (messageToProcess != null) {
					if (messageToProcess instanceof FragmentedHandshakeMessage) {
						messageToProcess = handleFragmentation((FragmentedHandshakeMessage) messageToProcess);
					}

					if (messageToProcess == null) {
						// messageToProcess is fragmented and not all parts have been received yet
					} else {
						// continue with the now fully re-assembled message
						if (messageToProcess instanceof GenericHandshakeMessage) {
							HandshakeParameter parameter = session.getParameter();
							if (parameter == null) {
								throw new IllegalStateException("handshake parameter are required!");
							}
							messageToProcess = ((GenericHandshakeMessage) messageToProcess)
									.getSpecificHandshakeMessage(parameter);
						}
						if (messageToProcess.getContentType() == ContentType.HANDSHAKE) {
							// only cancel on HANDSHAKE messages
							// the very last flight CCS + FINISH
							// must be not canceled before the FINISH
							DTLSFlight flight = pendingFlight.get();
							if (flight != null) {
								LOGGER.debug("response for flight {} started", flight.getFlightNumber());
								flight.setResponseStarted();
							}
						}
						doProcessMessage(messageToProcess);
					}

					// process next expected message (if available yet)
					messageToProcess = inboundMessageBuffer.getNextMessage();
				}
				session.markRecordAsRead(record.getEpoch(), record.getSequenceNumber());
			} catch (GeneralSecurityException e) {
				LOGGER.warn("Cannot process handshake message from peer [{}] due to [{}]", getSession().getPeer(),
						e.getMessage(), e);
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR,
						session.getPeer());
				throw new HandshakeException("Cannot process handshake message", alert);
			}
		} else if (sameEpoch) {
			LOGGER.trace("Discarding duplicate HANDSHAKE message received from peer [{}]:{}{}", record.getPeerAddress(),
					StringUtil.lineSeparator(), record);
		} else {
			LOGGER.trace("Discarding HANDSHAKE message with wrong epoch received from peer [{}]:{}{}",
					record.getPeerAddress(), StringUtil.lineSeparator(), record);
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
	 * @throws HandshakeException if the record's plaintext fragment cannot be parsed into
	 *            a handshake message or cannot be processed properly
	 * @throws GeneralSecurityException if the record's ciphertext fragment cannot be decrypted
	 */
	protected abstract void doProcessMessage(DTLSMessage message) throws HandshakeException, GeneralSecurityException;

	/**
	 * Starts the handshake by sending the first flight to the peer.
	 * <p>
	 * The particular message to be sent depends on this peer's role in the
	 * handshake, i.e. if this end represents the client or server.
	 * </p>
	 * 
	 * @throws HandshakeException if the message to start the handshake cannot be
	 *            created and sent using the session's current security parameters.
	 */
	public abstract void startHandshake() throws HandshakeException;

	// Methods ////////////////////////////////////////////////////////

	/**
	 * Initialize message digest for FINISH message.
	 * 
	 * @throw IllegalStateException if message digest is not available for this
	 *        platform. The supported message digest are checked by
	 *        {@link CipherSuite#isSupported()}.
	 */
	protected final void initMessageDigest() {
		String hashName = session.getCipherSuite().getPseudoRandomFunctionHashName();
		try {
			this.md = MessageDigest.getInstance(hashName);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(
					String.format("Message digest algorithm %s is not available on JVM", hashName));
		}
	}

	/**
	 * First, generates the master secret from the given premaster secret, set
	 * it in {@link #session}, and then applying the key expansion on the master
	 * secret generates a large enough key block to generate the write, MAC and
	 * IV keys. 
	 * 
	 * See <a href="http://tools.ietf.org/html/rfc5246#section-6.3">RFC5246</a>
	 * for further details about the keys.
	 * 
	 * @param premasterSecret
	 *            the shared premaster secret.
	 */
	protected final void generateKeys(byte[] premasterSecret) {
		byte[] masterSecret = generateMasterSecret(premasterSecret);
		session.setMasterSecret(masterSecret);

		calculateKeys(masterSecret);
	}

	/**
	 * Calculates the encryption key, MAC key and IV from a given master secret.
	 * First, applies the key expansion to the master secret.
	 * 
	 * @param masterSecret
	 *            the master secret.
	 */
	protected void calculateKeys(byte[] masterSecret) {
		/*
		 * Create keys as suggested in
		 * http://tools.ietf.org/html/rfc5246#section-6.3:
		 * client_write_MAC_key[SecurityParameters.mac_key_length]
		 * server_write_MAC_key[SecurityParameters.mac_key_length]
		 * client_write_key[SecurityParameters.enc_key_length]
		 * server_write_key[SecurityParameters.enc_key_length]
		 * client_write_IV[SecurityParameters.fixed_iv_length]
		 * server_write_IV[SecurityParameters.fixed_iv_length]
		 */

		String prfMacName = session.getCipherSuite().getPseudoRandomFunctionMacName();
		int macKeyLength = session.getCipherSuite().getMacKeyLength();
		int encKeyLength = session.getCipherSuite().getEncKeyLength();
		int fixedIvLength = session.getCipherSuite().getFixedIvLength();
		int totalLength = (macKeyLength + encKeyLength + fixedIvLength) * 2;
		// See http://tools.ietf.org/html/rfc5246#section-6.3:
		//      key_block = PRF(SecurityParameters.master_secret, "key expansion",
		//                      SecurityParameters.server_random + SecurityParameters.client_random);
		byte[] seed = ByteArrayUtils.concatenate(serverRandom.getRandomBytes(), clientRandom.getRandomBytes());
		byte[] data = PseudoRandomFunction.doPRF(prfMacName, masterSecret, Label.KEY_EXPANSION_LABEL, seed, totalLength);


		int index = 0;
		int length = macKeyLength;
		clientWriteMACKey = new SecretKeySpec(data, index, length, "Mac");
		index += length;
		serverWriteMACKey = new SecretKeySpec(data, index, length, "Mac");
		index += length;

		length = encKeyLength;
		clientWriteKey = new SecretKeySpec(data, index, length, "AES");
		index += length;
		serverWriteKey = new SecretKeySpec(data, index, length, "AES");
		index += length;

		length = fixedIvLength;
		clientWriteIV = new IvParameterSpec(data, index, length);
		index += length;
		serverWriteIV = new IvParameterSpec(data, index, length);
	}

	/**
	 * Generates the master secret from a given shared premaster secret as
	 * described in 
	 * <a href="http://tools.ietf.org/html/rfc5246#section-8.1">RFC5246</a>.
	 * 
	 * <pre>
	 * master_secret = PRF(pre_master_secret, "master secret",
	 * 	ClientHello.random + ServerHello.random) [0..47]
	 * </pre>
	 * 
	 * @param premasterSecret
	 *            the shared premaster secret.
	 * @return the master secret.
	 */
	private byte[] generateMasterSecret(byte[] premasterSecret) {
		String prfMacName = session.getCipherSuite().getPseudoRandomFunctionMacName();
		byte[] randomSeed = ByteArrayUtils.concatenate(clientRandom.getRandomBytes(), serverRandom.getRandomBytes());
		return PseudoRandomFunction.doPRF(prfMacName, premasterSecret, Label.MASTER_SECRET_LABEL, randomSeed);
	}

	/**
	 * The premaster secret is formed as follows: if the PSK is N octets long,
	 * concatenate a uint16 with the value N, N zero octets, a second uint16
	 * with the value N, and the PSK itself.
	 * 
	 * @param psk - preshared key as byte array
	 * @param otherSecret - either is zeroes (plain PSK case) or comes 
	 * from the EC Diffie-Hellman exchange (ECDHE_PSK). 
	 * @see <a href="http://tools.ietf.org/html/rfc4279#section-2">RFC 4279</a>
	 * @return byte array with generated premaster secret.
	 */
	protected final byte[] generatePremasterSecretFromPSK(byte[] psk, byte[] otherSecret) {
		/*
		 * What we are building is the following with length fields in between:
		 * struct { opaque other_secret<0..2^16-1>; opaque psk<0..2^16-1>; };
		 */
		int pskLength = psk.length;
		
		byte[] other = otherSecret == null ? new byte[pskLength] : otherSecret;
		DatagramWriter writer = new DatagramWriter();
		writer.write(other.length, 16);
		writer.writeBytes(other);
		writer.write(pskLength, 16);
		writer.writeBytes(psk);
		return writer.toByteArray();	
	}

	protected final void setCurrentReadState() {
		DTLSConnectionState connectionState;
		if (isClient) {
			connectionState = new DTLSConnectionState(session.getCipherSuite(), session.getCompressionMethod(), serverWriteKey, serverWriteIV, serverWriteMACKey);
		} else {
			connectionState = new DTLSConnectionState(session.getCipherSuite(), session.getCompressionMethod(), clientWriteKey, clientWriteIV, clientWriteMACKey);
		}
		session.setReadState(connectionState);
	}

	protected final void setCurrentWriteState() {
		DTLSConnectionState connectionState;
		if (isClient) {
			connectionState = new DTLSConnectionState(session.getCipherSuite(), session.getCompressionMethod(), clientWriteKey, clientWriteIV, clientWriteMACKey);
		} else {
			connectionState = new DTLSConnectionState(session.getCipherSuite(), session.getCompressionMethod(), serverWriteKey, serverWriteIV, serverWriteMACKey);
		}
		session.setWriteState(connectionState);
	}

	/**
	 * Wraps a DTLS message fragment into (potentially multiple) DTLS records
	 * and add them to the flight.
	 * 
	 * Sets the record's epoch, sequence number and handles fragmentation for
	 * handshake messages.
	 * 
	 * @param flight the flight to add the wrapped messages
	 * @param fragment the message fragment
	 * @throws HandshakeException if the message could not be encrypted using
	 *             the session's current security parameters
	 */
	protected final void wrapMessage(DTLSFlight flight, DTLSMessage fragment) throws HandshakeException {

		try {
			switch (fragment.getContentType()) {
			case HANDSHAKE:
				wrapHandshakeMessage(flight, (HandshakeMessage) fragment);
				break;
			case CHANGE_CIPHER_SPEC:
				// CCS has only 1 byte payload and doesn't require fragmentation
				flight.addMessage(new Record(fragment.getContentType(), session.getWriteEpoch(),
						session.getSequenceNumber(), fragment, session, false, 0));
				break;
			default:
				throw new HandshakeException("Cannot create " + fragment.getContentType() + " record for flight",
						new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, session.getPeer()));
			}
		} catch (GeneralSecurityException e) {
			throw new HandshakeException("Cannot create record",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, session.getPeer()));
		}
	}

	private void wrapHandshakeMessage(DTLSFlight flight, HandshakeMessage handshakeMessage) throws GeneralSecurityException {
		setSequenceNumber(handshakeMessage);
		int messageLength = handshakeMessage.getMessageLength();
		int maxFragmentLength = session.getMaxFragmentLength();

		if (messageLength <= maxFragmentLength) {
			boolean useCid = handshakeMessage.getMessageType() == HandshakeType.FINISHED;
			flight.addMessage(new Record(ContentType.HANDSHAKE, session.getWriteEpoch(),
					session.getSequenceNumber(), handshakeMessage, session, useCid, 0));
			return;
		}

		// message needs to be fragmented
		LOGGER.debug("Splitting up {} message for [{}] into multiple fragments of max {} bytes",
				handshakeMessage.getMessageType(), handshakeMessage.getPeer(), maxFragmentLength);
		// create N handshake messages, all with the
		// same message_seq value as the original handshake message
		byte[] messageBytes = handshakeMessage.fragmentToByteArray();
		if (messageBytes.length != messageLength) {
			throw new IllegalStateException(
					"message length " + messageLength + " differs from message " + messageBytes.length + "!");
		}
		int messageSeq = handshakeMessage.getMessageSeq();
		int offset = 0;
		while (offset < messageLength) {
			int fragmentLength = maxFragmentLength;
			if (offset + fragmentLength > messageLength) {
				// the last fragment is normally shorter than the maximal size
				fragmentLength = messageLength - offset;
			}
			byte[] fragmentBytes = new byte[fragmentLength];
			System.arraycopy(messageBytes, offset, fragmentBytes, 0, fragmentLength);

			FragmentedHandshakeMessage fragmentedMessage =
					new FragmentedHandshakeMessage(
							handshakeMessage.getMessageType(),
							messageLength,
							messageSeq,
							offset,
							fragmentBytes,
							session.getPeer());

			offset += fragmentLength;

			flight.addMessage(new Record(ContentType.HANDSHAKE, session.getWriteEpoch(), session.getSequenceNumber(),
					fragmentedMessage, session, false, 0));
		}
	}

	/**
	 * Called when a fragmented handshake message is received. Checks if all
	 * fragments already here to reassemble the handshake message and if so,
	 * returns the whole handshake message.
	 * 
	 * @param fragment
	 *            the fragmented handshake message.
	 * @return the reassembled handshake message (if all fragments are available),
	 *         <code>null</code> otherwise.
	 * @throws HandshakeException
	 *             if the reassembled fragments cannot be parsed into a valid <code>HandshakeMessage</code>
	 */
	protected final HandshakeMessage handleFragmentation(FragmentedHandshakeMessage fragment) throws HandshakeException {

		LOGGER.debug("Processing {} message fragment ...", fragment.getMessageType());
		
		if (fragment.getMessageLength() > maxFragmentedHandshakeMessageLength) {
			throw new HandshakeException(
					"Fragmented message length exceeded (" + fragment.getMessageLength() + " > " + maxFragmentedHandshakeMessageLength + ")!",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER, fragment.getPeer()));
		}
		int messageSeq = fragment.getMessageSeq();
		ReassemblingHandshakeMessage reassembledMessage = reassembledMessages.get(messageSeq);
		try {
			if (reassembledMessage == null) {
				reassembledMessage = new ReassemblingHandshakeMessage(fragment);
				reassembledMessages.put(messageSeq, reassembledMessage);
			}
			else {
				reassembledMessage.add(fragment);
			}
			if (reassembledMessage.isComplete()) {
				HandshakeMessage message = HandshakeMessage.fromByteArray(reassembledMessage.toByteArray(),
						session.getParameter(), reassembledMessage.getPeer());
				LOGGER.debug("Successfully re-assembled {} message", message.getMessageType());
				reassembledMessages.remove(messageSeq);
				return message;
			}
		} catch (IllegalArgumentException ex) {
			throw new HandshakeException(ex.getMessage(),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER, fragment.getPeer()));
		}
		
		return null;
	}

	// Getters and Setters ////////////////////////////////////////////

	protected final KeyExchangeAlgorithm getKeyExchangeAlgorithm() {
		return session.getKeyExchange();
	}

	final SecretKey getClientWriteMACKey() {
		return clientWriteMACKey;
	}

	final SecretKey getServerWriteMACKey() {
		return serverWriteMACKey;
	}

	final IvParameterSpec getClientWriteIV() {
		return clientWriteIV;
	}

	final IvParameterSpec getServerWriteIV() {
		return serverWriteIV;
	}

	final SecretKey getClientWriteKey() {
		return clientWriteKey;
	}

	final SecretKey getServerWriteKey() {
		return serverWriteKey;
	}

	/**
	 * Gets the session this handshaker is used to establish.
	 * 
	 * @return the session
	 */
	public final DTLSSession getSession() {
		return session;
	}

	/**
	 * Gets the IP address and port of the peer this handshaker is used to
	 * negotiate a session with.
	 * 
	 * @return the peer address
	 */
	public final InetSocketAddress getPeerAddress() {
		return session.getPeer();
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
	 * Sets the message sequence number on an outbound handshake message.
	 * 
	 * Also increases the sequence number counter afterwards.
	 * 
	 * @param message
	 *            the handshake message to set the <em>message_seq</em> on
	 */
	private void setSequenceNumber(HandshakeMessage message) {
		message.setMessageSeq(sequenceNumber);
		sequenceNumber++;
	}

	final int getNextReceiveSeq() {
		return nextReceiveSeq;
	}

	final void incrementNextReceiveSeq() {
		this.nextReceiveSeq++;
	}

	public void addApplicationDataForDeferredProcessing(RawData outgoingMessage) {
		// backwards compatibility, allow on outgoing message to be stored.
		int max = maxDeferredProcessedApplicationDataMessages == 0 ? 1 : maxDeferredProcessedApplicationDataMessages;
		if (deferredApplicationData.size() < max) {
			deferredApplicationData.add(outgoingMessage);
		}
	}

	public void addRecordsForDeferredProcessing(Record incomingMessage) {
		if (deferredRecords.size() < maxDeferredProcessedApplicationDataMessages) {
			deferredRecords.add(incomingMessage);
		}
	}

	public List<RawData> takeDeferredApplicationData() {
		List<RawData> applicationData = new ArrayList<RawData>(deferredApplicationData);
		deferredApplicationData.clear();
		return applicationData;
	}

	public List<Record> takeDeferredRecords() {
		List<Record> records = new ArrayList<Record>(deferredRecords);
		deferredRecords.clear();
		return records;
	}

	public void takeDeferredApplicationData(Handshaker replacedHandshaker) {
		deferredApplicationData.addAll(replacedHandshaker.takeDeferredApplicationData());
	}

	/**
	 * Registers an outbound flight that has not been acknowledged by the peer
	 * yet in order to be able to cancel its re-transmission later once it has
	 * been acknowledged. The retransmission of a different previous pending
	 * flight will be cancelled also.
	 * 
	 * @param pendingFlight the flight
	 */
	public void setPendingFlight(DTLSFlight pendingFlight) {
		DTLSFlight flight = this.pendingFlight.getAndSet(pendingFlight);
		if (flight != null && flight != pendingFlight) {
			flight.setResponseCompleted();
		}
	}

	public void sendFlight(DTLSFlight flight) {
		setPendingFlight(null);
		try {
			recordLayer.sendFlight(flight, connection);
			setPendingFlight(flight);
		} catch(IOException e) {
			handshakeFailed(new Exception("handshake flight " + flight.getFlightNumber() + " failed!", e));
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

	protected final void handshakeStarted() throws HandshakeException {
		for (SessionListener sessionListener : sessionListeners) {
			sessionListener.handshakeStarted(this);
		}
	}

	protected final void sessionEstablished() throws HandshakeException {
		if (!sessionEstablished) {
			sessionEstablished = true;
			for (SessionListener sessionListener : sessionListeners) {
				sessionListener.sessionEstablished(this, this.getSession());
			}
		}
	}

	public final void handshakeCompleted() {
		setPendingFlight(null);
		for (SessionListener sessionListener : sessionListeners) {
			sessionListener.handshakeCompleted(this);
		}
	}

	/**
	 * Notifies all registered session listeners about a handshake
	 * failure.
	 * 
	 * @param cause The reason for the failure.
	 */
	public final void handshakeFailed(Throwable cause) {
		if (!handshakeFailed) {
			handshakeFailed = true;
			setPendingFlight(null);
			if (!sessionEstablished) {
				for (SessionListener sessionListener : sessionListeners) {
					sessionListener.handshakeFailed(this, cause);
				}
				for (RawData message : takeDeferredApplicationData()) {
					message.onError(cause);
				}
			}
		}
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
	 * Checks whether this handshake has been initiated receiving the provided
	 * client hello.
	 * 
	 * The client random in the client message is used to check the duplicate.
	 * Only server handshaker are started receiving a client hello.
	 * 
	 * @param clientHello the client_hello to check.
	 * @return @{code true} if the provided client hello has initially started
	 *         this handshake.
	 */
	public boolean hasBeenStartedByClientHello(final ClientHello clientHello) {
		return false;
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
	 * Validates the X.509 certificate chain provided by the the peer as part of
	 * this message, or the raw public key.
	 *
	 * This method delegates the certificate chain validation to the
	 * {@link CertificateVerifier}
	 *
	 * OR
	 *
	 * checks that the raw public key is in the raw public key trust store.
	 *
	 * @param message the certificate message
	 *
	 * @throws HandshakeException if any of the checks fails
	 */
	public void verifyCertificate(CertificateMessage message) throws HandshakeException {
		if (message.getCertificateChain() != null) {
			if (certificateVerifier != null) {
				certificateVerifier.verifyCertificate(message, session);
			} else {
				LOGGER.debug("Certificate validation failed: x509 could not be trusted!");
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE,
						session.getPeer());
				throw new HandshakeException("Trust is not possible!", alert);
			}
		} else {
			RawPublicKeyIdentity rpk = new RawPublicKeyIdentity(message.getPublicKey());
			if (!rpkStore.isTrusted(rpk)) {
				LOGGER.debug("Certificate validation failed: Raw public key is not trusted");
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE,
						session.getPeer());
				throw new HandshakeException("Raw public key is not trusted", alert);
			}
		}
	}
}
