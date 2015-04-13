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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

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

	// Logging ////////////////////////////////////////////////////////

	private static final String MESSAGE_DIGEST_ALGORITHM_NAME = "SHA-256";

	protected static final Logger LOGGER = Logger.getLogger(Handshaker.class.getCanonicalName());

	// Static members /////////////////////////////////////////////////

	private final static int MASTER_SECRET_LABEL = 1;

	private final static int KEY_EXPANSION_LABEL = 2;

	public final static int CLIENT_FINISHED_LABEL = 3;

	public final static int SERVER_FINISHED_LABEL = 4;

	public final static int TEST_LABEL = 5;

	public final static int TEST_LABEL_2 = 6;

	public final static int TEST_LABEL_3 = 7;
	
	

	// Members ////////////////////////////////////////////////////////

	/**
	 * Indicates whether this handshaker performs the client or server part of
	 * the  protocol.
	 */
	protected boolean isClient;

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

	protected DTLSSession session = null;

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
	protected Map<Integer, List<FragmentedHandshakeMessage>> fragmentedMessages = new HashMap<Integer, List<FragmentedHandshakeMessage>>();

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
	
	
	// Constructor ////////////////////////////////////////////////////

	/**
	 * Creates a new handshaker for negotiating a DTLS session with a given peer.
	 * 
	 * @param isClient
	 *            indicates whether this handshaker plays the client or server role
	 * @param session
	 *            the session this handshaker is negotiating
	 * @param rootCertificates
	 *            the trusted root certificates
	 * @param maxFragmentLength the maximum length of message fragments this handshaker
	 *            may send to the peer
	 * @throws HandshakeException if the message digest required for computing
	 *            the handshake hash cannot be instantiated
	 * @throws NullPointerException if session is <code>null</code>
	 */
	protected Handshaker(boolean isClient, DTLSSession session, Certificate[] rootCertificates,
			int maxFragmentLength) throws HandshakeException {
		this(isClient, 0, session, rootCertificates, maxFragmentLength);
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
	 * @param rootCertificates
	 *            the trusted root certificates
	 * @param maxFragmentLength the maximum length of message fragments this handshaker
	 *            may send to the peer
	 * @throws HandshakeException if the message digest required for computing
	 *            the FINISHED message hash cannot be instantiated
	 * @throws NullPointerException if session is <code>null</code>
	 * @throws IllegalArgumentException if the initial message sequence number is negative
	 */
	protected Handshaker(boolean isClient, int initialMessageSeq, DTLSSession session, Certificate[] rootCertificates,
			int maxFragmentLength) throws HandshakeException {
		if (session == null) {
			throw new NullPointerException("DTLS Session must not be null");
		}
		if (initialMessageSeq < 0) {
			throw new IllegalArgumentException("Initial message sequence number must not be negative");
		}
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
			LOGGER.log(Level.SEVERE,"Could not initialize message digest algorithm for Handshaker.", e);
			throw new HandshakeException("Could not initialize handshake",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR));
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
					new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR));
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
	 * @throws HandshakeException
	 *             if the handshake cannot be completed successfully
	 */
	public final DTLSFlight processMessage(Record message) throws HandshakeException {
		DTLSFlight nextFlight = null;
		// The DTLS 1.2 spec (section 4.1.2.6) advises to do replay detection
		// before MAC validation based on the record's sequence numbers
		// see http://tools.ietf.org/html/rfc6347#section-4.1.2.6
		if (!session.isDuplicate(message.getSequenceNumber())) {
			message.setSession(session);
			nextFlight = doProcessMessage(message);
			session.markRecordAsRead(message.getEpoch(), message.getSequenceNumber());
		} else {
			LOGGER.log(Level.FINER, "Discarding duplicate HANDSHAKE message received from peer [{0}]:\n{1}",
					new Object[]{getPeerAddress(), message});
		}
		return nextFlight;
	}
	
	/**
	 * Does the specific processing of a record received from a peer in
	 * the course of an ongoing handshake.
	 * 
	 * This method does not do anything. Concrete handshaker implementations should
	 * override this method in order to do prepare the response to the received
	 * record.
	 * 
	 * @param record the record received from the peer
	 * @return the handshake messages to send to the peer in response to the
	 *            received record
	 * @throws HandshakeException if the handshake cannot be completed successfully
	 */
	protected DTLSFlight doProcessMessage(Record record) throws HandshakeException {
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
	 */
	public abstract DTLSFlight getStartHandshakeMessage();

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

		int macKeyLength = cipherSuite.getBulkCipher().getMacKeyLength();
		int encKeyLength = cipherSuite.getBulkCipher().getEncKeyLength();
		int fixedIvLength = cipherSuite.getBulkCipher().getFixedIvLength();

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

	/**
	 * Does the Pseudorandom function as defined in <a
	 * href="http://tools.ietf.org/html/rfc5246#section-5">RFC 5246</a>.
	 * 
	 * @param secret
	 *            the secret
	 * @param labelId
	 *            the label
	 * @param seed
	 *            the seed
	 * @return the byte[]
	 */
	public static final byte[] doPRF(byte[] secret, int labelId, byte[] seed) {
		try {
			MessageDigest md = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM_NAME);

			String label;
			switch (labelId) {
			case MASTER_SECRET_LABEL:
				// The master secret is always 48 bytes long, see
				// http://tools.ietf.org/html/rfc5246#section-8.1
				label = "master secret";
				return doExpansion(md, secret, ByteArrayUtils.concatenate(label.getBytes(), seed), 48);

			case KEY_EXPANSION_LABEL:
				// The most key material required is 128 bytes, see
				// http://tools.ietf.org/html/rfc5246#section-6.3
				label = "key expansion";
				return doExpansion(md, secret, ByteArrayUtils.concatenate(label.getBytes(), seed), 128);

			case CLIENT_FINISHED_LABEL:
				// The verify data is always 12 bytes long, see
				// http://tools.ietf.org/html/rfc5246#section-7.4.9
				label = "client finished";
				return doExpansion(md, secret, ByteArrayUtils.concatenate(label.getBytes(), seed), 12);

			case SERVER_FINISHED_LABEL:
				// The verify data is always 12 bytes long, see
				// http://tools.ietf.org/html/rfc5246#section-7.4.9
				label = "server finished";
				return doExpansion(md, secret, ByteArrayUtils.concatenate(label.getBytes(), seed), 12);

			case TEST_LABEL:
				// http://www.ietf.org/mail-archive/web/tls/current/msg03416.html
				label = "test label";
				return doExpansion(md, secret, ByteArrayUtils.concatenate(label.getBytes(), seed), 100);

			case TEST_LABEL_2:
				// http://www.ietf.org/mail-archive/web/tls/current/msg03416.html
				label = "test label";
				md = MessageDigest.getInstance("SHA-512");
				return doExpansion(md, secret, ByteArrayUtils.concatenate(label.getBytes(), seed), 196);

			case TEST_LABEL_3:
				// http://www.ietf.org/mail-archive/web/tls/current/msg03416.html
				label = "test label";
				md = MessageDigest.getInstance("SHA-384");
				return doExpansion(md, secret, ByteArrayUtils.concatenate(label.getBytes(), seed), 148);

			default:
				LOGGER.severe("Unknwon label: " + labelId);
				return null;
			}
		} catch (NoSuchAlgorithmException e) {
			LOGGER.log(Level.SEVERE,"Message digest algorithm not available.",e);
			return null;
		}
	}

	/**
	 * Performs the secret expansion as described in <a
	 * href="http://tools.ietf.org/html/rfc5246#section-5">RFC 5246</a>.
	 * 
	 * @param md
	 *            the cryptographic hash function.
	 * @param secret
	 *            the secret.
	 * @param data
	 *            the data.
	 * @param length
	 *            the length of the expansion in <tt>bytes</tt>.
	 * @return the expanded array with given length.
	 */
	protected static final byte[] doExpansion(MessageDigest md, byte[] secret, byte[] data, int length) {
		/*
		 * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
		 * HMAC_hash(secret, A(2) + seed) + HMAC_hash(secret, A(3) + seed) + ...
		 * where + indicates concatenation. A() is defined as: A(0) = seed, A(i)
		 * = HMAC_hash(secret, A(i-1))
		 */
		double hashLength = 32;
		if (md.getAlgorithm().equals("SHA-1")) {
			hashLength = 20;
		} else if (md.getAlgorithm().equals("SHA-384")) {
			hashLength = 48;
		}

		int iterations = (int) Math.ceil(length / hashLength);
		byte[] expansion = new byte[0];

		byte[] A = data;
		for (int i = 0; i < iterations; i++) {
			A = doHMAC(md, secret, A);
			expansion = ByteArrayUtils.concatenate(expansion, doHMAC(md, secret, ByteArrayUtils.concatenate(A, data)));
		}

		return ByteArrayUtils.truncate(expansion, length);
	}

	/**
	 * Performs the HMAC computation as described in <a
	 * href="http://tools.ietf.org/html/rfc2104#section-2">RFC 2104</a>.
	 * 
	 * @param md
	 *            the cryptographic hash function.
	 * @param secret
	 *            the secret key.
	 * @param data
	 *            the data.
	 * @return the hash after HMAC has been applied.
	 */
	public static final byte[] doHMAC(MessageDigest md, byte[] secret, byte[] data) {
		// the block size of the hash function, always 64 bytes (for SHA-512 it
		// would be 128 bytes, but not needed right now, except for test
		// purpose)

		int B = 64;
		if (md.getAlgorithm().equals("SHA-512") || md.getAlgorithm().equals("SHA-384")) {
			B = 128;
		}

		// See http://tools.ietf.org/html/rfc2104#section-2
		// ipad = the byte 0x36 repeated B times
		byte[] ipad = new byte[B];
		Arrays.fill(ipad, (byte) 0x36);

		// opad = the byte 0x5C repeated B times
		byte[] opad = new byte[B];
		Arrays.fill(opad, (byte) 0x5C);

		/*
		 * (1) append zeros to the end of K to create a B byte string (e.g., if
		 * K is of length 20 bytes and B=64, then K will be appended with 44
		 * zero bytes 0x00)
		 */
		byte[] step1 = secret;
		if (secret.length < B) {
			// append zeros to the end of K to create a B byte string
			step1 = ByteArrayUtils.padArray(secret, (byte) 0x00, B);
		} else if (secret.length > B) {
			// Applications that use keys longer
			// than B bytes will first hash the key using H and then use the
			// resultant L byte string as the actual key to HMAC.
			md.update(secret);
			step1 = md.digest();
			md.reset();

			step1 = ByteArrayUtils.padArray(step1, (byte) 0x00, B);
		}

		/*
		 * (2) XOR (bitwise exclusive-OR) the B byte string computed in step (1)
		 * with ipad
		 */
		byte[] step2 = ByteArrayUtils.xorArrays(step1, ipad);

		/*
		 * (3) append the stream of data 'text' to the B byte string resulting
		 * from step (2)
		 */
		byte[] step3 = ByteArrayUtils.concatenate(step2, data);

		/*
		 * (4) apply H to the stream generated in step (3)
		 */
		md.update(step3);
		byte[] step4 = md.digest();
		md.reset();

		/*
		 * (5) XOR (bitwise exclusive-OR) the B byte string computed in step (1)
		 * with opad
		 */
		byte[] step5 = ByteArrayUtils.xorArrays(step1, opad);

		/*
		 * (6) append the H result from step (4) to the B byte string resulting
		 * from step (5)
		 */
		byte[] step6 = ByteArrayUtils.concatenate(step5, step4);

		/*
		 * (7) apply H to the stream generated in step (6) and output the result
		 */
		md.update(step6);
		byte[] step7 = md.digest();

		return step7;
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
	 */
	protected final List<Record> wrapMessage(DTLSMessage fragment) {
		
		List<Record> records = new ArrayList<Record>();

		ContentType type = null;
		if (fragment instanceof ApplicationMessage) {
			type = ContentType.APPLICATION_DATA;
		} else if (fragment instanceof AlertMessage) {
			type = ContentType.ALERT;
		} else if (fragment instanceof ChangeCipherSpecMessage) {
			type = ContentType.CHANGE_CIPHER_SPEC;
		} else if (fragment instanceof HandshakeMessage) {
			type = ContentType.HANDSHAKE;
			HandshakeMessage handshakeMessage = (HandshakeMessage) fragment;
			setSequenceNumber(handshakeMessage);
			
			byte[] messageBytes = handshakeMessage.fragmentToByteArray();
			
			if (messageBytes.length > maxFragmentLength) {
				/*
				 * The sender then creates N handshake messages, all with the
				 * same message_seq value as the original handshake message.
				 */
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
							new FragmentedHandshakeMessage(fragmentBytes, handshakeMessage.getMessageType(), offset, messageBytes.length);
					
					// all fragments have the same message_seq
					fragmentedMessage.setMessageSeq(messageSeq);
					offset += fragmentBytes.length;
					
					records.add(new Record(type, session.getWriteEpoch(), session.getSequenceNumber(), fragmentedMessage, session));
				}
			}
		}
		
		if (records.isEmpty()) { // no fragmentation needed
			records.add(new Record(type, session.getWriteEpoch(), session.getSequenceNumber(), fragment, session));
		}
		
		return records;
	}

	
	/**
	 * Determines, using the epoch and sequence number, whether this record is
	 * the next one which needs to be processed by the handshake protocol.
	 * 
	 * @param record the current received message.
	 * @return <tt>true</tt> if the current message is the next to process,
	 *         <tt>false</tt> otherwise.
	 * @throws HandshakeException
	 *             if DTLS handshake fails 
	 */
	protected final boolean processMessageNext(Record record) throws HandshakeException {

		int epoch = record.getEpoch();
		if (epoch < session.getReadEpoch()) {
			// discard old message
			LOGGER.log(Level.FINER, "Discarding message from previous epoch from peer [{0}]", getPeerAddress());
			return false;
		} else if (epoch == session.getReadEpoch()) {
			DTLSMessage fragment = record.getFragment();
			if (fragment instanceof AlertMessage) {
				return true; // Alerts must be processed immediately
			} else if (fragment instanceof ChangeCipherSpecMessage) {
				return true; // CCS must be processed immediately
			} else if (fragment instanceof HandshakeMessage) {
				int messageSeq = ((HandshakeMessage) fragment).getMessageSeq();

				if (messageSeq == nextReceiveSeq) {
					if (!(fragment instanceof FragmentedHandshakeMessage)) {
						// each fragment has the same message_seq, therefore
						// don't increment yet
						incrementNextReceiveSeq();
					}
					return true;
				} else if (messageSeq > nextReceiveSeq) {
					LOGGER.log(Level.FINER, "Queued newer message from same epoch, message_seq [{0}], next_receive_seq [{1}]",
							new Object[]{messageSeq, nextReceiveSeq});
					queuedMessages.add(record);
					return false;
				} else {
					LOGGER.log(Level.FINER, "Discarding old message, message_seq [{0}], next_receive_seq [{1}]",
							new Object[]{messageSeq, nextReceiveSeq});
					return false;
				}
			} else {
				LOGGER.log(Level.FINER, "Cannot process HANDSHAKE message of unknwon type");
				return false;
			}
		} else {
			// newer epoch, queue message
			queuedMessages.add(record);
			LOGGER.log(Level.FINER, "Queueing HANDSHAKE message from epoch [{0}] > current epoch [{1}]",
					new Object[]{record.getEpoch(), getSession().getReadEpoch()});
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
	 * @return the reassembled handshake message (if all fragements available),
	 *         <code>null</code> otherwise.
	 * @throws HandshakeException
	 *             if DTLS handshake fails
	 */
	protected final HandshakeMessage handleFragmentation(FragmentedHandshakeMessage fragment) throws HandshakeException {
		HandshakeMessage reassembledMessage = null;
		
		int messageSeq = fragment.getMessageSeq();
		if (fragmentedMessages.get(messageSeq) == null) {
			fragmentedMessages.put(messageSeq, new ArrayList<FragmentedHandshakeMessage>());
		}
		// store fragment together with other fragments of same message_seq
		fragmentedMessages.get(messageSeq).add(fragment);
		
		reassembledMessage = reassembleFragments(messageSeq, fragment.getMessageLength(), fragment.getMessageType(), session);
		if (reassembledMessage != null) {
			// message could be reassembled, therefore increase the next_receive_seq
			incrementNextReceiveSeq();
			fragmentedMessages.remove(messageSeq);
		}
		
		return reassembledMessage;
	}
	
	/**
	 * Tries to reassemble the handshake message with the available fragments.
	 * 
	 * @param messageSeq
	 *            the fragment's message_seq
	 * @param totalLength
	 *            the expected total length of the reassembled fragment
	 * @param type
	 *            the type of the handshake message
	 * @param session
	 *            the {@link DTLSSession}
	 * @return the reassembled handshake message (if all fragements available),
	 *         <code>null</code> otherwise.
	 * @throws HandshakeException
	 *             if DTLS handshake fails
	 */
	protected final HandshakeMessage reassembleFragments(int messageSeq, int totalLength, HandshakeType type, DTLSSession session) throws HandshakeException {
		List<FragmentedHandshakeMessage> fragments = fragmentedMessages.get(messageSeq);
		HandshakeMessage message = null;

		// sort according to fragment offset
		Collections.sort(fragments, new Comparator<FragmentedHandshakeMessage>() {

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
			FragmentedHandshakeMessage wholeMessage = new FragmentedHandshakeMessage(type, totalLength, messageSeq, 0, reassembly);
			reassembly = wholeMessage.toByteArray();
			
			KeyExchangeAlgorithm keyExchangeAlgorithm = KeyExchangeAlgorithm.NULL;
			boolean receiveRawPublicKey = false;
			if (session != null) {
				keyExchangeAlgorithm = session.getKeyExchange();
				receiveRawPublicKey = session.receiveRawPublicKey();
			}
			message = HandshakeMessage.fromByteArray(reassembly, keyExchangeAlgorithm, receiveRawPublicKey);
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
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE));
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
}
