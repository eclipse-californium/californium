/*******************************************************************************
 * Copyright (c) 2014, 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.util.ByteArrayUtils;


/**
 * A base class for the DTLS handshake protocol.
 * 
 * Contains all functionality and fields needed by all types of handshakers.
 */
public abstract class Handshaker {

	public final static int MASTER_SECRET_LABEL = 1;

	public final static int KEY_EXPANSION_LABEL = 2;

	public final static int CLIENT_FINISHED_LABEL = 3;

	public final static int SERVER_FINISHED_LABEL = 4;

	private static final String MESSAGE_DIGEST_ALGORITHM_NAME = "SHA-256";

	private static final Logger LOGGER = Logger.getLogger(Handshaker.class.getName());

	/**
	 * Indicates whether this handshaker performs the client or server part of
	 * the  protocol.
	 */
	protected final boolean isClient;

	protected int state = -1;

	protected ProtocolVersion usedProtocol;
	protected Random clientRandom;
	protected Random serverRandom;
	private CipherSuite cipherSuite;
	private CompressionMethod compressionMethod;

	protected KeyExchangeAlgorithm keyExchange;

	/** The helper class to execute the ECDHE key agreement and key generation. */
	protected ECDHECryptography ecdhe;

	private byte[] masterSecret;

	private SecretKey clientWriteMACKey;
	private SecretKey serverWriteMACKey;

	private IvParameterSpec clientWriteIV;
	private IvParameterSpec serverWriteIV;

	private SecretKey clientWriteKey;
	private SecretKey serverWriteKey;

	protected final DTLSSession session;

	/**
	 * The current sequence number (in the handshake message called message_seq)
	 * for this handshake.
	 */
	private int sequenceNumber = 0;

	/** The next expected handshake message sequence number. */
	private int nextReceiveSeq = 0;

	/** Buffer for received records that can not be processed immediately. */
	protected Collection<Record> queuedMessages;
	
	/** Store the fragmented messages until we are able to reassemble the handshake message. */
	protected Map<Integer, SortedSet<FragmentedHandshakeMessage>> fragmentedMessages = new HashMap<Integer, SortedSet<FragmentedHandshakeMessage>>();

	/**
	 * The message digest to compute the handshake hashes sent in the
	 * {@link Finished} messages.
	 */
	protected MessageDigest md;

	/** All the handshake messages exchanged before the CertificateVerify message. */
	protected byte[] handshakeMessages = new byte[] {};

	/**
	 * The last flight that is sent during this handshake, will not be
	 * retransmitted unless the peer retransmits its last flight.
	 */
	protected DTLSFlight lastFlight = null;

	/** The handshaker's private key. */
	protected PrivateKey privateKey;

	/** The handshaker's public key. */
	protected PublicKey publicKey;

	/** The handshaker's certificate chain. */
	protected Certificate[] certificates;
	
	/** list of trusted self-signed root certificates */
	protected final Certificate[] rootCertificates;
	
	/** the maximum fragment size before DTLS fragmentation must be applied */
	private int maxFragmentLength = 4096;

	private SessionListener sessionListener;
	
	
	// Constructor ////////////////////////////////////////////////////

	/**
	 * Creates a new handshaker for negotiating a DTLS session with a given peer.
	 * 
	 * @param isClient
	 *            indicates whether this handshaker plays the client or server role
	 * @param session
	 *            the session this handshaker is negotiating
	 * @param sessionListener
	 *            the listener to notify about the session's life-cycle events
	 * @param rootCertificates
	 *            the trusted root certificates
	 * @param maxFragmentLength the maximum length of message fragments this handshaker
	 *            may send to the peer
	 * @throws HandshakeException if the message digest required for computing
	 *            the handshake hash cannot be instantiated
	 * @throws NullPointerException if session is <code>null</code>
	 */
	protected Handshaker(boolean isClient, DTLSSession session, SessionListener sessionListener, 
			Certificate[] rootCertificates, int maxFragmentLength) throws HandshakeException {
		this(isClient, 0, session, sessionListener, rootCertificates, maxFragmentLength);
	}
	
	/**
	 * Creates a new handshaker for negotiating a DTLS session with a given peer.
	 * 
	 * @param isClient
	 *            indicates whether this handshaker plays the client or server role
	 * @param initialMessageSeq
	 *            the initial message sequence number to use and expect in the exchange
	 *            of handshake messages with the peer. This parameter can be used to
	 *            initialize the <em>message_seq</em> and <em>receive_next_seq</em>
	 *            counters to a value larger than 0, e.g. if one or more cookie exchange
	 *            round-trips have been performed with the peer before the handshake starts.
	 * @param session
	 *            the session this handshaker is negotiating
	 * @param sessionListener
	 *            the listener to notify about the session's life-cycle events
	 * @param rootCertificates
	 *            the trusted root certificates
	 * @param maxFragmentLength the maximum length of message fragments this handshaker
	 *            may send to the peer
	 * @throws HandshakeException if the message digest required for computing
	 *            the FINISHED message hash cannot be instantiated
	 * @throws NullPointerException if session is <code>null</code>
	 * @throws IllegalArgumentException if the initial message sequence number is negative
	 */
	protected Handshaker(boolean isClient, int initialMessageSeq, DTLSSession session, SessionListener sessionListener,
			Certificate[] rootCertificates, int maxFragmentLength) throws HandshakeException {
		if (session == null) {
			throw new NullPointerException("DTLS Session must not be null");
		}
		if (initialMessageSeq < 0) {
			throw new IllegalArgumentException("Initial message sequence number must not be negative");
		}
		this.sessionListener = sessionListener;
		this.nextReceiveSeq = initialMessageSeq;
		this.sequenceNumber = initialMessageSeq;
		this.isClient = isClient;
		this.session = session;
		this.queuedMessages = new HashSet<Record>();
		this.rootCertificates = rootCertificates == null ? new Certificate[0] : rootCertificates;	
		this.maxFragmentLength = maxFragmentLength;

		try {
			this.md = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM_NAME);
		} catch (NoSuchAlgorithmException e) {
			throw new HandshakeException("Could not initialize message digest algorithm for Handshaker",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, session.getPeer()));
		}
	}
	
	/**
	 * 
	 * @param peerAddress
	 *            the peer's address.
	 * @param isClient
	 *            indicates whether this handshaker plays the client or server role
	 * @param session
	 *            the session this handshaker is negotiating
	 * @param rootCertificates
	 *            the trusted root certificates
	 * @throws HandshakeException if the message digest required for computing
	 *            the handshake hash cannot be instantiated
	 * @throws NullPointerException if session is <code>null</code>
	 * @throws IllegalArgumentException if the given peer address differs from the one
	 *            contained in the session
	 * @deprecated Use one of the other constructors
	 */
	public Handshaker(InetSocketAddress peerAddress, boolean isClient, DTLSSession session,
			Certificate[] rootCertificates) throws HandshakeException {
		if (session == null) {
			throw new NullPointerException("DTLS Session must not be null");
		} else if (!session.getPeer().equals(peerAddress)) {
			throw new IllegalArgumentException("Peer address must be the same as in session");
		}
		this.isClient = isClient;
		this.session = session;
		this.queuedMessages = new HashSet<Record>();
		this.rootCertificates = rootCertificates == null ? new Certificate[0] : rootCertificates;	

		try {
			this.md = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM_NAME);
		} catch (NoSuchAlgorithmException e) {
			LOGGER.log(Level.SEVERE,"Could not initialize message digest algorithm for Handshaker.", e);
			throw new HandshakeException("Could not initialize handshake",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, session.getPeer()));
		}
	}

	/**
	 * Processes a handshake record received from a peer based on the
	 * handshake's current state.
	 * 
	 * This method only does a duplicate check as described in
	 * <a href="http://tools.ietf.org/html/rfc6347#section-4.1.2.6">
     * section 4.1.2.6 of the DTLS 1.2 spec</a> and then delegates
     * processing of the record to the {@link #doProcessMessage(Record)}
     * method.
     * 
	 * @param message
	 *            the handshake record
	 * @return the handshake messages that need to be sent to the peer in
	 *            response to the record received or <code>null</code> if
	 *            the received record does not require a response to be sent
	 * @throws HandshakeException if the record's plaintext fragment cannot be parsed into
	 *            a handshake message or cannot be processed properly
	 */
	public final DTLSFlight processMessage(Record message) throws HandshakeException {
		DTLSFlight nextFlight = null;
		// The DTLS 1.2 spec (section 4.1.2.6) advises to do replay detection
		// before MAC validation based on the record's sequence numbers
		// see http://tools.ietf.org/html/rfc6347#section-4.1.2.6
		if (!session.isDuplicate(message.getSequenceNumber())) {
			try {
				message.setSession(session);
				nextFlight = doProcessMessage(message);
				session.markRecordAsRead(message.getEpoch(), message.getSequenceNumber());
			} catch (GeneralSecurityException e) {
				LOGGER.log(Level.WARNING,
						String.format(
								"Cannot process handshake message from peer [%s] due to [%s]",
								getSession().getPeer(), e.getMessage()),
						e);
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, session.getPeer());
				throw new HandshakeException("Cannot process handshake message", alert);
			}
		} else {
			LOGGER.log(Level.FINEST, "Discarding duplicate HANDSHAKE message received from peer [{0}]:\n{1}",
					new Object[]{message.getPeerAddress(), message});
		}
		return nextFlight;
	}
	
	/**
	 * Does the specific processing of a record received from a peer in
	 * the course of an ongoing handshake.
	 * 
	 * This method does not do anything. Concrete handshaker implementations should
	 * override this method in order to prepare the response to the received
	 * record.
	 * 
	 * @param record the record received from the peer
	 * @return the handshake messages to send to the peer in response to the
	 *            received record
	 * @throws HandshakeException if the record's plaintext fragment cannot be parsed into
	 *            a handshake message or cannot be processed properly
	 * @throws GeneralSecurityException if the record's ciphertext fragment cannot be decrypted
	 */
	protected DTLSFlight doProcessMessage(Record record) throws HandshakeException, GeneralSecurityException {
		return null;
	}

	/**
	 * Gets the handshake flight which needs to be sent first to initiate
	 * handshake.
	 * 
	 * The particular message to be sent depends on the role a peer plays in the
	 * handshake.
	 * 
	 * @return the handshake message to start off the handshake protocol.
	 * @throws HandshakeException if the message cannot be created using the
	 *            session's current security parameters
	 */
	public abstract DTLSFlight getStartHandshakeMessage() throws HandshakeException;

	// Methods ////////////////////////////////////////////////////////

	/**
	 * First, generates the master secret from the given premaster secret and
	 * then applying the key expansion on the master secret generates a large
	 * enough key block to generate the write, MAC and IV keys. See <a
	 * href="http://tools.ietf.org/html/rfc5246#section-6.3">RFC 5246</a> for
	 * further details about the keys.
	 * 
	 * @param premasterSecret
	 *            the shared premaster secret.
	 */
	protected final void generateKeys(byte[] premasterSecret) {
		masterSecret = generateMasterSecret(premasterSecret);
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
	private void calculateKeys(byte[] masterSecret) {
		/*
		 * See http://tools.ietf.org/html/rfc5246#section-6.3:
		 * key_block = PRF(SecurityParameters.master_secret, "key expansion", SecurityParameters.server_random + SecurityParameters.client_random);
		 */

		byte[] data = doPRF(masterSecret, KEY_EXPANSION_LABEL, ByteArrayUtils.concatenate(serverRandom.getRandomBytes(), clientRandom.getRandomBytes()));

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
		if (cipherSuite == null) {
			cipherSuite = session.getCipherSuite();
		}

		int macKeyLength = cipherSuite.getMacKeyLength();
		int encKeyLength = cipherSuite.getEncKeyLength();
		int fixedIvLength = cipherSuite.getFixedIvLength();

		clientWriteMACKey = new SecretKeySpec(data, 0, macKeyLength, "Mac");
		serverWriteMACKey = new SecretKeySpec(data, macKeyLength, macKeyLength, "Mac");

		clientWriteKey = new SecretKeySpec(data, 2 * macKeyLength, encKeyLength, "AES");
		serverWriteKey = new SecretKeySpec(data, (2 * macKeyLength) + encKeyLength, encKeyLength, "AES");

		clientWriteIV = new IvParameterSpec(data, (2 * macKeyLength) + (2 * encKeyLength), fixedIvLength);
		serverWriteIV = new IvParameterSpec(data, (2 * macKeyLength) + (2 * encKeyLength) + fixedIvLength, fixedIvLength);

	}

	/**
	 * Generates the master secret from a given shared premaster secret as
	 * described in <a href="http://tools.ietf.org/html/rfc5246#section-8.1">RFC
	 * 5246</a>.
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
		byte[] randomSeed = ByteArrayUtils.concatenate(clientRandom.getRandomBytes(), serverRandom.getRandomBytes());
		return doPRF(premasterSecret, MASTER_SECRET_LABEL, randomSeed);
	}

	/**
	 * See <a href="http://tools.ietf.org/html/rfc4279#section-2">RFC 4279</a>:
	 * The premaster secret is formed as follows: if the PSK is N octets long,
	 * concatenate a uint16 with the value N, N zero octets, a second uint16
	 * with the value N, and the PSK itself.
	 * 
	 * @param psk
	 *            the preshared key as byte array.
	 * @return the premaster secret.
	 */
	protected final byte[] generatePremasterSecretFromPSK(byte[] psk) {
		/*
		 * What we are building is the following with length fields in between:
		 * struct { opaque other_secret<0..2^16-1>; opaque psk<0..2^16-1>; };
		 */
		int length = psk.length;

		byte[] lengthField = new byte[2];
		lengthField[0] = (byte) (length >> 8);
		lengthField[1] = (byte) (length);

		byte[] zero = ByteArrayUtils.padArray(new byte[0], (byte) 0x00, length);

		byte[] premasterSecret = ByteArrayUtils.concatenate(lengthField, ByteArrayUtils.concatenate(zero, ByteArrayUtils.concatenate(lengthField, psk)));

		return premasterSecret;
	}

	static byte[] doPRF(byte[] secret, byte[] label, byte[] seed, int length) {
		try {
			Mac hmac = Mac.getInstance("HmacSHA256");
			hmac.init(new SecretKeySpec(secret, "MAC"));
			return doExpansion(hmac, ByteArrayUtils.concatenate(label, seed), length);
		} catch (GeneralSecurityException e) {
			LOGGER.log(Level.SEVERE, "Message digest algorithm not available", e);
			return null;
		}
		
	}
	
	/**
	 * Does the Pseudorandom function as defined in <a
	 * href="http://tools.ietf.org/html/rfc5246#section-5">RFC 5246</a>.
	 * 
	 * @param secret the secret to use for the secure hash function
	 * @param labelId the label to use for creating the original data
	 * @param seed the seed to use for creating the original data
	 * @return the expanded data
	 */
	static final byte[] doPRF(byte[] secret, int labelId, byte[] seed) {
		int length;
			String label;
			switch (labelId) {
			case MASTER_SECRET_LABEL:
				// The master secret is always 48 bytes long, see
				// http://tools.ietf.org/html/rfc5246#section-8.1
				label = "master secret";
			length = 48;
			break;
			case KEY_EXPANSION_LABEL:
				// The most key material required is 128 bytes, see
				// http://tools.ietf.org/html/rfc5246#section-6.3
				label = "key expansion";
			length = 128;
			break;

			case CLIENT_FINISHED_LABEL:
				// The verify data is always 12 bytes long, see
				// http://tools.ietf.org/html/rfc5246#section-7.4.9
				label = "client finished";
			length = 12;
			break;

			case SERVER_FINISHED_LABEL:
				// The verify data is always 12 bytes long, see
				// http://tools.ietf.org/html/rfc5246#section-7.4.9
				label = "server finished";
			length = 12;
			break;

			default:
			LOGGER.log(Level.SEVERE, "Unknown label: {0}", labelId);
				return null;
			}
		return doPRF(secret, label.getBytes(), seed, length);
	}

	/**
	 * Performs the secret expansion as described in <a
	 * href="http://tools.ietf.org/html/rfc5246#section-5">RFC 5246</a>.
	 * 
	 * @param hmac
	 *            the cryptographic hash function to use for expansion
	 * @param data
	 *            the data to expand
	 * @param length
	 *            the length to expand the data to in <tt>bytes</tt>
	 * @return the expanded data
	 */
	static final byte[] doExpansion(Mac hmac, byte[] data, int length) {
		/*
		 * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
		 * HMAC_hash(secret, A(2) + seed) + HMAC_hash(secret, A(3) + seed) + ...
		 * where + indicates concatenation. A() is defined as: A(0) = seed, A(i)
		 * = HMAC_hash(secret, A(i-1))
		 */

		int iterations = (int) Math.ceil(length / (double) hmac.getMacLength());
		byte[] expansion = new byte[0];

		byte[] A = data;
		for (int i = 0; i < iterations; i++) {
			A = hmac.doFinal(A);
			expansion = ByteArrayUtils.concatenate(expansion, hmac.doFinal(ByteArrayUtils.concatenate(A, data)));
		}

		return ByteArrayUtils.truncate(expansion, length);
	}

	protected final void setCurrentReadState() {
		DTLSConnectionState connectionState;
		if (isClient) {
			connectionState = new DTLSConnectionState(cipherSuite, compressionMethod, serverWriteKey, serverWriteIV, serverWriteMACKey);
		} else {
			connectionState = new DTLSConnectionState(cipherSuite, compressionMethod, clientWriteKey, clientWriteIV, clientWriteMACKey);
		}
		session.setReadState(connectionState);
	}

	protected final void setCurrentWriteState() {
		DTLSConnectionState connectionState;
		if (isClient) {
			connectionState = new DTLSConnectionState(cipherSuite, compressionMethod, clientWriteKey, clientWriteIV, clientWriteMACKey);
		} else {
			connectionState = new DTLSConnectionState(cipherSuite, compressionMethod, serverWriteKey, serverWriteIV, serverWriteMACKey);
		}
		session.setWriteState(connectionState);
	}

	/**
	 * Wraps a DTLS message fragment into (potentially multiple) DTLS records.
	 * 
	 * Sets the record's epoch, sequence number and handles fragmentation
	 * for handshake messages.
	 * 
	 * @param fragment
	 *            the message fragment
	 * @return the records containing the message fragment, ready to be sent to the
	 *            peer
	 * @throws HandshakeException if the message could not be encrypted using the session's
	 *            current security parameters
	 */
	protected final List<Record> wrapMessage(DTLSMessage fragment) throws HandshakeException {

		try {
			switch(fragment.getContentType()) {
			case HANDSHAKE:
				return wrapHandshakeMessage((HandshakeMessage) fragment);
			default:
				List<Record> records = new ArrayList<Record>();
				records.add(new Record(fragment.getContentType(), session.getWriteEpoch(), session.getSequenceNumber(),
						fragment, session));
				return records;
			}
		} catch (GeneralSecurityException e) {
			throw new HandshakeException(
					"Cannot create record",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, session.getPeer()));
		}
	}

	private List<Record> wrapHandshakeMessage(HandshakeMessage handshakeMessage) throws GeneralSecurityException {
		setSequenceNumber(handshakeMessage);
		List<Record> result = new ArrayList<>();
		byte[] messageBytes = handshakeMessage.fragmentToByteArray();
		
		if (messageBytes.length <= maxFragmentLength) {
			result.add(new Record(ContentType.HANDSHAKE, session.getWriteEpoch(), session.getSequenceNumber(), handshakeMessage, session));
		} else {
			// message needs to be fragmented
			// The sender then creates N handshake messages, all with the
			// same message_seq value as the original handshake message
			int messageSeq = handshakeMessage.getMessageSeq();

			int numFragments = (messageBytes.length / maxFragmentLength) + 1;
			
			int offset = 0;
			for (int i = 0; i < numFragments; i++) {
				int fragmentLength = maxFragmentLength;
				if (offset + fragmentLength > messageBytes.length) {
					// the last fragment is normally shorter than the maximal size
					fragmentLength = messageBytes.length - offset;
				}
				byte[] fragmentBytes = new byte[fragmentLength];
				System.arraycopy(messageBytes, offset, fragmentBytes, 0, fragmentLength);
				
				FragmentedHandshakeMessage fragmentedMessage =
						new FragmentedHandshakeMessage(fragmentBytes, handshakeMessage.getMessageType(), offset,
								messageBytes.length, session.getPeer());
				
				// all fragments have the same message_seq
				fragmentedMessage.setMessageSeq(messageSeq);
				offset += fragmentBytes.length;
				
				result.add(new Record(ContentType.HANDSHAKE, session.getWriteEpoch(), session.getSequenceNumber(), fragmentedMessage, session));
			}
		}
		return result;
	}
	
	/**
	 * Determines, using the epoch and sequence number, whether this record is
	 * the next one which needs to be processed by the handshake protocol.
	 * 
	 * @param record the current received message.
	 * @return <tt>true</tt> if the current message is the next to process,
	 *         <tt>false</tt> otherwise.
	 * @throws HandshakeException if the record's plaintext fragment could not be parsed
	 *           into a handshake message
	 * @throws GeneralSecurityException if the record's ciphertext fragment could not be decrypted 
	 */
	protected final boolean processMessageNext(Record record) throws HandshakeException, GeneralSecurityException {

		int epoch = record.getEpoch();
		if (epoch < session.getReadEpoch()) {
			// discard old message
			LOGGER.log(Level.FINER,
					"Discarding message from peer [{0}] from finished epoch [{1}] < current epoch [{2}]",
					new Object[]{getPeerAddress(), epoch, session.getReadEpoch()});
			return false;
		} else if (epoch == session.getReadEpoch()) {
			DTLSMessage fragment = record.getFragment();
			switch(fragment.getContentType()) {
			case ALERT:
			case CHANGE_CIPHER_SPEC:
				return true;
			case HANDSHAKE:
				int messageSeq = ((HandshakeMessage) fragment).getMessageSeq();

				if (messageSeq == nextReceiveSeq) {
					if (!(fragment instanceof FragmentedHandshakeMessage)) {
						// each fragment has the same message_seq, therefore
						// don't increment yet
						incrementNextReceiveSeq();
					}
					return true;
				} else if (messageSeq > nextReceiveSeq) {
					LOGGER.log(Level.FINER,
							"Queued newer message from same epoch, message_seq [{0}] > next_receive_seq [{1}]",
							new Object[]{messageSeq, nextReceiveSeq});
					queuedMessages.add(record);
					return false;
				} else {
					LOGGER.log(Level.FINER,
							"Discarding old message, message_seq [{0}] < next_receive_seq [{1}]",
							new Object[]{messageSeq, nextReceiveSeq});
					return false;
				}
			default:
				LOGGER.log(Level.FINER, "Cannot process HANDSHAKE message of unknown type");
				return false;
			}
		} else {
			// newer epoch, queue message
			queuedMessages.add(record);
			LOGGER.log(Level.FINER,
					"Queueing HANDSHAKE message from future epoch [{0}] > current epoch [{1}]",
					new Object[]{epoch, getSession().getReadEpoch()});
			return false;
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
		HandshakeMessage reassembledMessage = null;
		
		int messageSeq = fragment.getMessageSeq();
		SortedSet<FragmentedHandshakeMessage> existingFragments = fragmentedMessages.get(messageSeq);
		if (existingFragments == null) {
			existingFragments = new TreeSet<FragmentedHandshakeMessage>(new Comparator<FragmentedHandshakeMessage>() {

				// @Override
				public int compare(FragmentedHandshakeMessage o1, FragmentedHandshakeMessage o2) {
					if (o1.getFragmentOffset() == o2.getFragmentOffset()) {
						return 0;
					} else if (o1.getFragmentOffset() < o2.getFragmentOffset()) {
						return -1;
					} else {
						return 1;
					}
				}
			});
			fragmentedMessages.put(messageSeq, existingFragments);
		}
		// store fragment together with other fragments of same message_seq
		existingFragments.add(fragment);
		
		reassembledMessage = reassembleFragments(messageSeq, existingFragments,
				fragment.getMessageLength(), fragment.getMessageType(), session);
		if (reassembledMessage != null) {
			// message could be reassembled, therefore increase the next_receive_seq
			incrementNextReceiveSeq();
			fragmentedMessages.remove(messageSeq);
		}
		
		return reassembledMessage;
	}
	
	/**
	 * Reassembles handshake message fragments into the original message.
	 * 
	 * @param messageSeq
	 *            the fragment's message_seq
	 * @param fragments the fragments to reassemble
	 * @param totalLength
	 *            the expected total length of the reassembled fragment
	 * @param type
	 *            the type of the handshake message
	 * @param session
	 *            the {@link DTLSSession}
	 * @return the reassembled handshake message (if all fragements are available),
	 *         <code>null</code> otherwise.
	 * @throws HandshakeException
	 *             if the reassembled fragments cannot be parsed into a valid <code>HandshakeMessage</code>
	 */
	private final HandshakeMessage reassembleFragments(
			int messageSeq,
			SortedSet<FragmentedHandshakeMessage> fragments,
			int totalLength,
			HandshakeType type,
			DTLSSession session) throws HandshakeException {

		HandshakeMessage message = null;

		byte[] reassembly = new byte[] {};
		int offset = 0;
		for (FragmentedHandshakeMessage fragmentedHandshakeMessage : fragments) {
			
			int fragmentOffset = fragmentedHandshakeMessage.getFragmentOffset();
			int fragmentLength = fragmentedHandshakeMessage.getFragmentLength();
			
			if (fragmentOffset == offset) { // eliminate duplicates
				// case: no overlap
				reassembly = ByteArrayUtils.concatenate(reassembly, fragmentedHandshakeMessage.fragmentToByteArray());
				offset = reassembly.length;
			} else if (fragmentOffset < offset && (fragmentOffset + fragmentLength) > offset) {
				// case: overlap fragment
				
				// determine the offset where the fragment adds new information for the reassembly
				int newOffset = offset - fragmentOffset;
				int newLength = fragmentLength - newOffset;
				byte[] newBytes = new byte[newLength];
				// take only the new bytes and add them
				System.arraycopy(fragmentedHandshakeMessage.fragmentToByteArray(), newOffset, newBytes, 0, newLength);	
				reassembly = ByteArrayUtils.concatenate(reassembly, newBytes);
				
				offset = reassembly.length;
			}
		}
		
		if (reassembly.length == totalLength) {
			// the reassembled fragment has the expected length
			FragmentedHandshakeMessage wholeMessage =
					new FragmentedHandshakeMessage(type, totalLength, messageSeq, 0, reassembly, getPeerAddress());
			reassembly = wholeMessage.toByteArray();
			
			KeyExchangeAlgorithm keyExchangeAlgorithm = KeyExchangeAlgorithm.NULL;
			boolean receiveRawPublicKey = false;
			if (session != null) {
				keyExchangeAlgorithm = session.getKeyExchange();
				receiveRawPublicKey = session.receiveRawPublicKey();
			}
			message = HandshakeMessage.fromByteArray(reassembly, keyExchangeAlgorithm, receiveRawPublicKey, getPeerAddress());
		}
		
		return message;
	}

	// Getters and Setters ////////////////////////////////////////////

	final CipherSuite getCipherSuite() {
		return cipherSuite;
	}

	/**
	 * Sets the negotiated {@link CipherSuite} and the corresponding
	 * {@link KeyExchangeAlgorithm}.
	 * 
	 * @param cipherSuite the cipher suite.
	 * @throws HandshakeException if the given cipher suite is <code>null</code>
	 * 	or {@link CipherSuite#TLS_NULL_WITH_NULL_NULL}
	 */
	protected final void setCipherSuite(CipherSuite cipherSuite) throws HandshakeException {
		if (cipherSuite == null || CipherSuite.TLS_NULL_WITH_NULL_NULL == cipherSuite) {
			throw new HandshakeException("Negotiated cipher suite must not be null",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, session.getPeer()));
		}
		this.cipherSuite = cipherSuite;
		this.keyExchange = cipherSuite.getKeyExchange();
		this.session.setCipherSuite(cipherSuite);
	}

	final byte[] getMasterSecret() {
		return masterSecret;
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
	final DTLSSession getSession() {
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

	final CompressionMethod getCompressionMethod() {
		return compressionMethod;
	}

	final void setCompressionMethod(CompressionMethod compressionMethod) {
		this.compressionMethod = compressionMethod;
		// TODO is this right? Shouldn't this be done when pending state becomes current state only?
		this.session.setCompressionMethod(compressionMethod);
	}

	final int getMaxFragmentLength() {
		return maxFragmentLength;
	}

	/**
	 * Sets the maximum length of handshake messages that this handshaker
	 * may send in a single fragment.
	 * 
	 * @param maxFragmentLength the number of bytes
	 * @deprecated set this value using the constructor instead
	 */
	public final void setMaxFragmentLength(int maxFragmentLength) {
		this.maxFragmentLength = maxFragmentLength;
	}

	protected final void handshakeStarted() throws HandshakeException {
		if (sessionListener != null) {
			sessionListener.handshakeStarted(this);
		}
	}
	
	protected final void sessionEstablished() throws HandshakeException {
		if (sessionListener != null) {
			sessionListener.sessionEstablished(this, this.getSession());
		}
	}

	protected final void handshakeCompleted() {
		if (sessionListener != null) {
			sessionListener.handshakeCompleted(getPeerAddress());
		}
	}
}
