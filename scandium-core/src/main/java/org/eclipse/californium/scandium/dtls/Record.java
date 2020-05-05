/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - expose sequence number as
 *                   property of type long in order to prevent tedious conversions
 *                   in client code
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add initial support for Block Ciphers
 *    Achim Kraus (Bosch Software Innovations GmbH) - add isNewClientHello
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - use handshake parameter and
 *                                                    generic handshake messages to
 *                                                    process reordered handshake messages
 *    Achim Kraus (Bosch Software Innovations GmbH) - cleanup
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.cipher.InvalidMacException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An object representation of the DTLS <em>Record</em> layer data structure(s).
 * <p>
 * The <em>Datagram Transport Layer Security</em> specification defines
 * a set of data structures at the <a href="http://tools.ietf.org/html/rfc6347#section-4.3.1">
 * Record</a> layer containing the data to be exchanged with peers.
 * <p>
 * This class is used to transform these data structures from their binary encoding
 * as received from the network interface to their object representation and vice versa.
 */
public class Record {

	// Logging ////////////////////////////////////////////////////////

	private static final Logger LOGGER = LoggerFactory.getLogger(Record.class);

	// DTLS specific constants/////////////////////////////////////////

	public static final int CONTENT_TYPE_BITS = 8;

	public static final int VERSION_BITS = 8; // for major and minor each

	public static final int EPOCH_BITS = 16;

	public static final int SEQUENCE_NUMBER_BITS = 48;

	public static final int LENGTH_BITS = 16;

	public static final int CID_LENGTH_BITS = 8;

	public static final int RECORD_HEADER_BITS = CONTENT_TYPE_BITS + VERSION_BITS + VERSION_BITS +
			EPOCH_BITS + SEQUENCE_NUMBER_BITS + LENGTH_BITS;

	private static final long MAX_SEQUENCE_NO = 281474976710655L; // 2^48 - 1

	// Members ////////////////////////////////////////////////////////

	/** The higher-level protocol used to process the enclosed fragment */
	private ContentType type;

	/**
	 * The version of the protocol being employed. DTLS version 1.2 uses { 254, 253 }
	 */
	private final ProtocolVersion version;

	/** A counter value that is incremented on every cipher state change */
	private final int epoch;

	/** The sequence number for this record */
	private long sequenceNumber;
	/**
	 * Receive time in uptime nanoseconds.
	 * 
	 * @link {@link ClockUtil#nanoRealtime()}
	 */
	private final long receiveNanos;

	/**
	 * The application data. This data is transparent and treated as an
	 * independent block to be dealt with by the higher-level protocol specified
	 * by the type field.
	 */
	private DTLSMessage fragment;

	/** The raw byte representation of the fragment. */
	private byte[] fragmentBytes;

	/** The connection id. */
	private ConnectionId connectionId;

	/** Padding to be used with cid */
	private int padding;

	/**
	 * The DTLS write state for outgoing records.
	 * 
	 * Provided with the session passed in
	 * {@link #Record(ContentType, int, long, DTLSMessage, DTLSSession, boolean, int)}
	 */
	private final DTLSConnectionState outgoingWriteState;

	/**
	 * The DTLS session for incoming records. Required for additional parameters
	 * to decode handshake messages.
	 * 
	 * @see #applySession(DTLSSession)
	 */
	private DTLSSession incomingSession;

	/**
	 * The DTLS state for incoming records. Used incoming records and set by
	 * {@link #applySession(DTLSSession)}, when the epoch is reached.
	 */
	private DTLSConnectionState incomingReadState;

	/** The peer address. */
	private final InetSocketAddress peerAddress;

	// Constructors ///////////////////////////////////////////////////

	/**
	 * Creates a record from a <em>DTLSCiphertext</em> struct received from the network.
	 * 
	 * Called when reconstructing the record from a byte array. The fragment
	 * will remain in its binary representation up to the DTLS Layer.
	 * 
	 * @param type the content type. The new record type
	 *            {@link ContentType#TLS12_CID} is directly supported.
	 * @param version the version
	 * @param epoch the epoch
	 * @param sequenceNumber the sequence number
	 * @param connectionId the connection id
	 * @param fragmentBytes the encrypted data
	 * @param peerAddress peer address
	 * @param receiveNanos uptime nanoseconds of receiving this record
	 * @throws IllegalArgumentException if the given sequence number is longer
	 *             than 48 bits or less than 0. Or the given epoch is less than 0.
	 * @throws NullPointerException if the given type, protocol version,
	 *             fragment bytes or peer address is {@code null}.
	 */
	Record(ContentType type, ProtocolVersion version, int epoch, long sequenceNumber, ConnectionId connectionId,
			byte[] fragmentBytes, InetSocketAddress peerAddress, long receiveNanos) {
		this(version, epoch, sequenceNumber, receiveNanos, null, peerAddress);
		if (type == null) {
			throw new NullPointerException("Type must not be null");
		} else if (fragmentBytes == null) {
			throw new NullPointerException("Fragment bytes must not be null");
		} else if (peerAddress == null) {
			throw new NullPointerException("Peer address must not be null");
		}
		this.type = type;
		this.connectionId = connectionId;
		this.fragmentBytes = fragmentBytes;
	}

	/**
	 * Creates an outbound record containing a {@link DTLSMessage} as its
	 * payload.
	 * 
	 * The given <em>fragment</em> is encoded into its binary representation and
	 * encrypted according to the given session's current write state. In order
	 * to create a <code>Record</code> containing an un-encrypted fragment, use
	 * the {@link #Record(ContentType, long, DTLSMessage, InetSocketAddress)}
	 * constructor.
	 * 
	 * @param type the type of the record's payload. The new record type
	 *            {@link ContentType#TLS12_CID} is not supported directly.
	 *            Provide the inner type and {@code true} for the parameter cid
	 * @param epoch the epoch
	 * @param sequenceNumber the 48-bit sequence number
	 * @param fragment the payload
	 * @param session the session to determine the current write state from
	 * @param cid if {@code true} use write connection id from provided session.
	 *            Otherwise use {@code null} as connection id
	 * @param pad if cid is enabled, pad could be used to add that number of
	 *            zero-bytes as padding to the payload to obfuscate the payload
	 *            length.
	 * @throws IllegalArgumentException if the given sequence number is longer
	 *             than 48 bits or less than 0, the given epoch is less than 0,
	 *             the provided type is not supported or the fragment could not
	 *             be converted into bytes. Or the provided session doesn't have
	 *             a peer address.
	 * @throws NullPointerException if the given type, fragment or session is
	 *             {@code null}.
	 * @throws GeneralSecurityException if the message could not be encrypted,
	 *             e.g. because the JVM does not support the negotiated cipher
	 *             suite's cipher algorithm
	 */
	public Record(ContentType type, int epoch, long sequenceNumber, DTLSMessage fragment, DTLSSession session,
			boolean cid, int pad) throws GeneralSecurityException {
		this(new ProtocolVersion(), epoch, sequenceNumber, 0, session, null);
		if (fragment == null) {
			throw new NullPointerException("Fragment must not be null");
		} else if (session == null) {
			throw new NullPointerException("Session must not be null");
		} else if (session.getPeer() == null) {
			throw new IllegalArgumentException("Session's peer address must not be null");
		}
		setType(type);
		if (cid) {
			this.connectionId = session.getWriteConnectionId();
			this.padding = pad;
		}
		setEncodedFragment(fragment);
		if (fragmentBytes == null) {
			throw new IllegalArgumentException("Fragment missing encoded bytes!");
		}
	}

	/**
	 * Creates an outbound record representing a {@link DTLSMessage} as its payload.
	 * 
	 * The payload will be sent un-encrypted using epoch 0.
	 * Using {@link #updateSequenceNumber(long)} is not supported for these records.
	 * 
	 * @param type the type of the record's payload. The new record type
	 *            {@link ContentType#TLS12_CID} is not supported.
	 * @param sequenceNumber the 48-bit sequence number
	 * @param fragment the payload to send
	 * @param peerAddress the IP address and port of the peer this record should
	 *            be sent to
	 * @throws IllegalArgumentException if the given sequence number is longer
	 *             than 48 bits or less than 0, the given epoch is less than
	 *             0, or the fragment could not be converted into bytes.
	 * @throws NullPointerException if the given type, fragment or peer address
	 *             is {@code null}.
	 */
	public Record(ContentType type, long sequenceNumber, DTLSMessage fragment, InetSocketAddress peerAddress) {
		this(new ProtocolVersion(), 0, sequenceNumber, 0, null, peerAddress);
		if (fragment == null) {
			throw new NullPointerException("Fragment must not be null");
		} else if (peerAddress == null) {
			throw new NullPointerException("Peer address must not be null");
		}
		setType(type);
		this.fragment = fragment;
		this.fragmentBytes = fragment.toByteArray();
		if (fragmentBytes == null) {
			throw new IllegalArgumentException("Fragment missing encoded bytes!");
		}
	}

	private Record(ProtocolVersion version, int epoch, long sequenceNumber, long receiveNanos, DTLSSession session, InetSocketAddress peer) {
		if (sequenceNumber > MAX_SEQUENCE_NO) {
			throw new IllegalArgumentException("Sequence number must be 48 bits only! " + sequenceNumber);
		} else if (sequenceNumber < 0) {
			throw new IllegalArgumentException("Sequence number must not be less than 0! " + sequenceNumber);
		} else if (epoch < 0) {
			throw new IllegalArgumentException("Epoch must not be less than 0! " + epoch);
		} else if (version == null) {
			throw new NullPointerException("Version must not be null");
		}
		this.version = version;
		this.epoch = epoch;
		this.sequenceNumber = sequenceNumber;
		this.receiveNanos = receiveNanos;
		this.outgoingWriteState = session == null ? null : session.getWriteState();
		if (peer == null && session != null) {
			this.peerAddress = session.getPeer();
		} else {
			this.peerAddress = peer;
		}
	}

	// Serialization //////////////////////////////////////////////////

	/**
	 * Encodes this record into its corresponding <em>DTLSCiphertext</em> structure.
	 * 
	 * @return a byte array containing the <em>DTLSCiphertext</em> structure
	 */
	public byte[] toByteArray() {
		DatagramWriter writer = new DatagramWriter();

		if (useConnectionId()) {
			writer.write(ContentType.TLS12_CID.getCode(), CONTENT_TYPE_BITS);
		} else {
			writer.write(type.getCode(), CONTENT_TYPE_BITS);
		}

		writer.write(version.getMajor(), VERSION_BITS);
		writer.write(version.getMinor(), VERSION_BITS);

		writer.write(epoch, EPOCH_BITS);
		writer.writeLong(sequenceNumber, SEQUENCE_NUMBER_BITS);
		if (useConnectionId()) {
			writer.writeBytes(connectionId.getBytes());
		}
		writer.write(fragmentBytes.length, LENGTH_BITS);
		writer.writeBytes(fragmentBytes);

		return writer.toByteArray();
	}

	public int size() {
		return RECORD_HEADER_BITS / Byte.SIZE + getFragmentLength();
	}

	/**
	 * Parses a sequence of <em>DTLSCiphertext</em> structures into {@code Record}> instances.
	 * 
	 * The binary representation is expected to comply with the <em>DTLSCiphertext</em> structure
	 * defined in <a href="http://tools.ietf.org/html/rfc6347#section-4.3.1">RFC6347, Section 4.3.1</a>.
	 * 
	 * @param byteArray the raw binary representation containing one or more DTLSCiphertext structures
	 * @param peerAddress the IP address and port of the peer from which the bytes have been
	 *           received
	 * @param cidGenerator the connection id generator. May be {@code null}.
	 * @param receiveNanos uptime nanoseconds of receiving this record
	 * @return the {@code Record} instances
	 * @throws NullPointerException if either one of the byte array or peer address is {@code null}
	 */
	public static List<Record> fromByteArray(byte[] byteArray, InetSocketAddress peerAddress, ConnectionIdGenerator cidGenerator, long receiveNanos) {
		if (byteArray == null) {
			throw new NullPointerException("Byte array must not be null");
		} else if (peerAddress == null) {
			throw new NullPointerException("Peer address must not be null");
		}

		List<Record> records = new ArrayList<Record>();

		DatagramReader reader = new DatagramReader(byteArray, false);

		while (reader.bytesAvailable()) {

			if (reader.bitsLeft() < RECORD_HEADER_BITS) {
				LOGGER.debug("Received truncated DTLS record(s). Discarding ...");
				return records;
			}

			int type = reader.read(CONTENT_TYPE_BITS);
			int major = reader.read(VERSION_BITS);
			int minor = reader.read(VERSION_BITS);
			ProtocolVersion version = new ProtocolVersion(major, minor);

			int epoch = reader.read(EPOCH_BITS);
			long sequenceNumber = reader.readLong(SEQUENCE_NUMBER_BITS);

			ConnectionId connectionId = null;
			if (type == ContentType.TLS12_CID.getCode()) {
				if (cidGenerator == null) {
					LOGGER.debug("Received TLS_CID record, but cid is not supported. Discarding ...");
					return records;
				} else if (cidGenerator.useConnectionId()) {
					try {
						connectionId = cidGenerator.read(reader);
						if (connectionId == null) {
							LOGGER.debug("Received TLS_CID record, but cid is not matching. Discarding ...");
							return records;
						}
					} catch (RuntimeException ex) {
						LOGGER.debug("Received TLS_CID record, failed to read cid. Discarding ...", ex.getMessage());
						return records;
					}
				} else {
					LOGGER.debug("Received TLS_CID record, but cid is not used. Discarding ...");
					return records;
				}
			}
			int length = reader.read(LENGTH_BITS);

			if (reader.bitsLeft() < (length * Byte.SIZE)) {
				LOGGER.debug("Received truncated DTLS record(s). Discarding ...");
				return records;
			}

			// delay decryption/interpretation of fragment
			byte[] fragmentBytes = reader.readBytes(length);

			ContentType contentType = ContentType.getTypeByValue(type);
			if (contentType == null) {
				LOGGER.debug("Received DTLS record of unsupported type [{}]. Discarding ...", type);
			} else {
				records.add(new Record(contentType, version, epoch, sequenceNumber, connectionId, fragmentBytes,
						peerAddress, receiveNanos));
			}
		}

		return records;
	}

	// Cryptography Helper Methods ////////////////////////////////////

	/**
	 * Generates the explicit part of the nonce to be used with the AEAD Cipher.
	 * 
	 * <a href="http://tools.ietf.org/html/rfc6655#section-3">RFC6655, Section 3</a>
	 * encourages the use of the session's 16bit epoch value concatenated
	 * with a monotonically increasing 48bit sequence number as the explicit nonce. 
	 * 
	 * @return the 64-bit explicit nonce constructed from the epoch and sequence number
	 */
	protected byte[] generateExplicitNonce() {
		
		//TODO: re-factor to use simple byte array manipulation instead of using bit-based DatagramWriter
		DatagramWriter writer = new DatagramWriter();
		
		writer.write(epoch, EPOCH_BITS);
		writer.writeLong(sequenceNumber, SEQUENCE_NUMBER_BITS);
		
		return writer.toByteArray();
	}

	/**
	 * See <a href="http://tools.ietf.org/html/rfc5246#section-6.2.3.3">RFC 5246</a>:
	 * 
	 * <pre>
	 * additional_data = seq_num + TLSCompressed.type +
	 *                   TLSCompressed.version + TLSCompressed.length;
	 * </pre>
	 * 
	 * where "+" denotes concatenation.
	 * 
	 * For the new tls_cid record, currently defined in
	 * <a href="https://datatracker.ietf.org/doc/draft-ietf-tls-dtls-connection-id/">Draft dtls-connection-id</a>
	 * this is extended by the conneciton id:
	 * 
	 * <pre>
	 * additional_data = seq_num + TLSCompressed.type + TLSCompressed.version + 
	 *                   connection_id + connection_id_length + TLSCompressed.length;
	 * </pre>
	 * 
	 * with the connection_id_length encoded in one uint8 byte.
	 * 
	 * @return the additional authentication data.
	 */
	protected byte[] generateAdditionalData(int length) {
		DatagramWriter writer = new DatagramWriter();
		
		writer.write(epoch, EPOCH_BITS);
		writer.writeLong(sequenceNumber, SEQUENCE_NUMBER_BITS);

		if (useConnectionId()) {
			writer.write(ContentType.TLS12_CID.getCode(), CONTENT_TYPE_BITS);
		} else {
			writer.write(type.getCode(), CONTENT_TYPE_BITS);
		}
		writer.write(version.getMajor(), VERSION_BITS);
		writer.write(version.getMinor(), VERSION_BITS);
		if (useConnectionId()) {
			writer.writeBytes(connectionId.getBytes());
			writer.write(connectionId.length(), CID_LENGTH_BITS);
		}
		writer.write(length, LENGTH_BITS);

		return writer.toByteArray();
	}

	// Getters and Setters ////////////////////////////////////////////

	/**
	 * Check, if record is CLIENT_HELLO of epoch 0.
	 * 
	 * This is important to detect a new association according RFC6347, section 4.2.8.
	 * 
	 * @return {@code true}, if record contains CLIENT_HELLO of epoch 0,
	 *         {@code false} otherwise.
	 */
	public boolean isNewClientHello() {
		if (0 < epoch || type != ContentType.HANDSHAKE || 0 == fragmentBytes.length) {
			return false;
		}
		HandshakeType handshakeType = HandshakeType.getTypeByCode(fragmentBytes[0]);
		return handshakeType == HandshakeType.CLIENT_HELLO;
	}

	public ContentType getType() {
		return type;
	}

	public ProtocolVersion getVersion() {
		return version;
	}

	public int getEpoch() {
		return epoch;
	}

	public long getSequenceNumber() {
		return sequenceNumber;
	}

	/**
	 * Update the record's sequence number for outgoing records.
	 * 
	 * Used, if record needs to be re-transmitted with a new sequence number.
	 * Requires record to be created using
	 * {@link #Record(ContentType, int, long, DTLSMessage, DTLSSession, boolean, int)}.
	 * 
	 * This method also takes care of re-encrypting the record's message
	 * fragment in order to update the ciphertext's MAC which is parameterized
	 * with the record's sequence number.
	 * 
	 * @param sequenceNumber the new sequence number
	 * @throws GeneralSecurityException if the fragment could not be
	 *             re-encrypted
	 * @throws IllegalArgumentException if the given sequence number is longer
	 *             than 48 bits or less than 0.
	 * @throws IllegalStateException if {@link #fragment} or
	 *             {@link #outgoingWriteState} is {@code null}. Indicate, that
	 *             record is not created with
	 *             {@link #Record(ContentType, int, long, DTLSMessage, DTLSSession, boolean, int)}
	 */
	public void updateSequenceNumber(long sequenceNumber) throws GeneralSecurityException {
		if (sequenceNumber > MAX_SEQUENCE_NO) {
			throw new IllegalArgumentException("Sequence number must have max 48 bits");
		} else if (sequenceNumber < 0) {
			throw new IllegalArgumentException("Sequence number must not be smaller than 0! " + sequenceNumber);
		} else if (fragment == null) {
			throw new IllegalStateException("Fragment must not be null!");
		} else if (outgoingWriteState == null) {
			throw new IllegalStateException("Write state must not be null!");
		}
		if (this.sequenceNumber != sequenceNumber) {
			this.sequenceNumber = sequenceNumber;
			if (epoch > 0) {
				// encrypt only again, if epoch 1 is reached!
				setEncodedFragment(fragment);
			}
		}
	}

	/**
	 * Gets the length of the fragment contained in this record in bytes.
	 * <p>
	 * The overall length of this record's <em>DTLSCiphertext</em>
	 * representation is thus <code>Record.length</code> + 13 (DTLS record headers)
	 * bytes.
	 * 
	 * @return the fragment length excluding record headers
	 */
	public int getFragmentLength() {
		return fragmentBytes.length;
	}

	/**
	 * Apply session for incoming records.
	 * 
	 * Apply session and decrypt fragment.
	 * 
	 * @param session session to apply. If {@code null} is provided,
	 *            {@link DTLSConnectionState#NULL} is used for de-cryption.
	 * @throws GeneralSecurityException if de-cryption fails, e.g. because the
	 *             JVM does not support the negotiated cipher algorithm, or
	 *             decoding of the inner plain text of
	 *             {@link ContentType#TLS12_CID} fails.
	 * @throws HandshakeException if the TLSPlaintext.fragment could not be
	 *             parsed into a valid handshake message
	 * @throws IllegalArgumentException if the record's and session's read epoch
	 *             doesn't match or a session with different read state is
	 *             applied after the record was decrypted.
	 */
	public void applySession(DTLSSession session) throws GeneralSecurityException, HandshakeException {
		int readEpoch;
		DTLSConnectionState readState;
		if (session == null) {
			readEpoch = 0;
			readState = DTLSConnectionState.NULL;
		} else {
			readEpoch = session.getReadEpoch();
			readState = session.getReadState();
		}
		if (readEpoch != epoch) {
			throw new IllegalArgumentException("session for different epoch! session " + readEpoch + " != record " + epoch);
		}
		
		if (fragment != null) {
			if (incomingReadState != readState) {
				LOGGER.error("{} != {}", readState, incomingReadState);
				throw new IllegalArgumentException("session read state changed!");
			}
		} else {
			this.incomingSession = session;
			this.incomingReadState = readState;
			decodeFragment();
		}
	}

	/**
	 * Get peer address.
	 * 
	 * @return peer address
	 */
	public InetSocketAddress getPeerAddress() {
		if (peerAddress == null) {
			throw new NullPointerException("missing peer address!");
		}
		return peerAddress;
	}

	/**
	 * Get connection id.
	 * 
	 * @return connection id
	 */
	public ConnectionId getConnectionId() {
		return connectionId;
	}

	/**
	 * Get uptime nanoseconds receiving this record.
	 * 
	 * @return uptime nanoseconds, or {@code 0}, if records wasn't received.
	 */
	public long getReceiveNanos() {
		return receiveNanos;
	}

	/**
	 * Get fragment payload as byte array.
	 * 
	 * @return fragments byte array.
	 */
	public byte[] getFragmentBytes() {
		return fragmentBytes;
	}

	/**
	 * Gets the object representation of this record's
	 * <em>DTLSPlaintext.fragment</em>.
	 * 
	 * For incoming records, the fragment is only available after the session of
	 * the epoch is {@link #applySession(DTLSSession)}.
	 * 
	 * @return the plaintext fragment
	 * @throws IllegalStateException if plaint-text fragment is not available
	 */
	public DTLSMessage getFragment() {
		if (fragment == null) {
			throw new IllegalStateException("fragment not decoded!");
		}
		return fragment;
	}

	/**
	 * Decode the object representation of this record's
	 * <em>DTLSPlaintext.fragment</em>.
	 * 
	 * If the record uses the new record type {@link ContentType#TLS12_CID} the
	 * {@link #type} is updated with the type of the inner plaintext.
	 * 
	 * @throws InvalidMacException if message authentication failed
	 * @throws GeneralSecurityException if de-cryption fails, e.g. because the
	 *             JVM does not support the negotiated cipher algorithm, or
	 *             decoding of the inner plain text of
	 *             {@link ContentType#TLS12_CID} fails.
	 * @throws HandshakeException if the TLSPlaintext.fragment could not be
	 *             parsed into a valid handshake message
	 */
	private void decodeFragment()
			throws GeneralSecurityException, HandshakeException {
		ContentType actualType = type;
		// decide, which type of fragment need de-cryption
		byte[] decryptedMessage = incomingReadState.decrypt(this, fragmentBytes);

		if (ContentType.TLS12_CID == type) {
			int index = decryptedMessage.length - 1;
			while (index >= 0 && decryptedMessage[index] == 0) {
				--index;
			}
			if (index < 0) {
				throw new GeneralSecurityException("no inner type!");
			}
			int typeCode = decryptedMessage[index];
			actualType =  ContentType.getTypeByValue(typeCode);
			if (actualType == null) {
				throw new GeneralSecurityException("unknown inner type! " + typeCode);
			}
			decryptedMessage = Arrays.copyOf(decryptedMessage, index);
		}

		switch (actualType) {
		case ALERT:
			// http://tools.ietf.org/html/rfc5246#section-7.2:
			// "Like other messages, alert messages are encrypted and
			// compressed, as specified by the current connection state."
			fragment = AlertMessage.fromByteArray(decryptedMessage, getPeerAddress());
			break;

		case APPLICATION_DATA:
			// http://tools.ietf.org/html/rfc5246#section-7.2:
			// "Like other messages, alert messages are encrypted and
			// compressed, as specified by the current connection state."
			fragment = ApplicationMessage.fromByteArray(decryptedMessage, getPeerAddress());
			break;

		case CHANGE_CIPHER_SPEC:
			// http://tools.ietf.org/html/rfc5246#section-7.1:
			// "is encrypted and compressed under the current (not the pending)
			// connection state"
			fragment = ChangeCipherSpecMessage.fromByteArray(decryptedMessage, getPeerAddress());
			break;

		case HANDSHAKE:
			fragment = handshakeMessageFromByteArray(decryptedMessage);
			break;

		default:
			LOGGER.debug("Cannot decrypt message of unsupported type [{}]", type);
		}
		type = actualType;
	}

	private DTLSMessage handshakeMessageFromByteArray(byte[] decryptedMessage) throws GeneralSecurityException, HandshakeException {
		if (LOGGER.isTraceEnabled()) {
			LOGGER.trace("Parsing HANDSHAKE message plaintext{}{}", StringUtil.lineSeparator(),
					StringUtil.byteArray2HexString(decryptedMessage));
		}

		HandshakeParameter parameter = null;
		if (incomingSession != null) {
			parameter = incomingSession.getParameter();
			LOGGER.trace("Parsing HANDSHAKE message plaintext with parameter [{}]", parameter);
		} else {
			LOGGER.trace("Parsing HANDSHAKE message without a session");
		}
		return HandshakeMessage.fromByteArray(decryptedMessage, parameter, getPeerAddress());
	}

	/**
	 * Sets the DTLS fragment. At the same time, it creates the corresponding
	 * raw binary representation and encrypts it if necessary (depending on
	 * current connection state). If cid is used, create also the "inner plain
	 * text" containing the payload, the original record type, and optional
	 * padding with zeros before encryption.
	 * 
	 * @param fragment the DTLS fragment
	 * @throws GeneralSecurityException if the message could not be encrypted,
	 *             e.g. because the JVM does not support the negotiated cipher
	 *             suite's cipher algorithm
	 * @throws NullPointerException if {@link DTLSMessage#toByteArray()} return
	 *             {@code null}.
	 * @see #useConnectionId()
	 */
	private void setEncodedFragment(DTLSMessage fragment) throws GeneralSecurityException {
		// serialize fragment and if necessary encrypt byte array
		byte[] byteArray = fragment.toByteArray();
		if (byteArray == null) {
			throw new NullPointerException("fragment must not return null");
		}
		if (useConnectionId()) {
			int index = byteArray.length;
			byteArray = Arrays.copyOf(byteArray, index + 1 + padding);
			byteArray[index] = (byte) type.getCode();
		}
		this.fragmentBytes = outgoingWriteState.encrypt(this, byteArray);
		this.fragment = fragment;
	}

	/**
	 * Check, if new tls_cid record must be used.
	 * 
	 * See <a href=
	 * "https://datatracker.ietf.org/doc/draft-ietf-tls-dtls-connection-id/">Draft dtls-connection-id</a> 
	 * 2019-feb-18: the last discussion agreement is NOT to use a empty CID for tls_cid records.
	 * 
	 * @return {@code true}, if a none empty cid is used.
	 * @see #Record(ContentType, int, long, DTLSMessage, DTLSSession, boolean,
	 *      int)
	 */
	boolean useConnectionId() {
		return connectionId != null && !connectionId.isEmpty();
	}

	private void setType(ContentType type) {
		if (type == null) {
			throw new NullPointerException("Type must not be null");
		}
		switch (type) {
		case ALERT:
		case APPLICATION_DATA:
		case HANDSHAKE:
		case CHANGE_CIPHER_SPEC:
			this.type = type;
			break;

		default:
			throw new IllegalArgumentException("Not supported content type: " + type);
		}
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("==[ DTLS Record ]==============================================");
		sb.append(StringUtil.lineSeparator()).append("Content Type: ").append(type.toString());
		sb.append(StringUtil.lineSeparator()).append("Peer address: ").append(getPeerAddress());
		sb.append(StringUtil.lineSeparator()).append("Version: ").append(version.getMajor()).append(", ").append(version.getMinor());
		sb.append(StringUtil.lineSeparator()).append("Epoch: ").append(epoch);
		sb.append(StringUtil.lineSeparator()).append("Sequence Number: ").append(sequenceNumber);
		if (connectionId != null) {
			sb.append(StringUtil.lineSeparator()).append("connection id: ").append(connectionId.getAsString());
		}
		sb.append(StringUtil.lineSeparator()).append("Length: ").append(fragmentBytes.length);
		sb.append(StringUtil.lineSeparator()).append("Fragment:");
		if (fragment != null) {
			sb.append(StringUtil.lineSeparator()).append(fragment);
		} else {
			sb.append(StringUtil.lineSeparator()).append("fragment is not decrypted yet");
		}
		sb.append(StringUtil.lineSeparator()).append("===============================================================");

		return sb.toString();
	}

}
