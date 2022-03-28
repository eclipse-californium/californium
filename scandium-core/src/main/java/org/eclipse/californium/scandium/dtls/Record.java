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
 * The <em>Datagram Transport Layer Security</em> specification defines a set of
 * data structures at the
 * <a href="https://tools.ietf.org/html/rfc6347#section-4.3.1" target="_blank">
 * Record</a> layer containing the data to be exchanged with peers.
 * <p>
 * This class is used to transform these data structures from their binary
 * encoding as received from the network interface to their object
 * representation and vice versa.
 */
public class Record {

	private static final Logger LOGGER = LoggerFactory.getLogger(Record.class);

	public static final int CONTENT_TYPE_BITS = 8;

	public static final int VERSION_BITS = 8; // for major and minor each

	public static final int EPOCH_BITS = 16;

	public static final int SEQUENCE_NUMBER_BITS = 48;

	public static final int LENGTH_BITS = 16;

	public static final int CID_LENGTH_BITS = 8;

	public static final int RECORD_HEADER_BITS = CONTENT_TYPE_BITS + VERSION_BITS + VERSION_BITS + EPOCH_BITS
			+ SEQUENCE_NUMBER_BITS + LENGTH_BITS;

	/**
	 * Bytes for dtls record header.
	 * 
	 * @since 2.4
	 */
	public static final int RECORD_HEADER_BYTES = RECORD_HEADER_BITS / Byte.SIZE;

	/**
	 * The payload length of all headers of a DTLS handshake message payload.
	 * <ol>
	 * <li>12 bytes DTLS handshake message header</li>
	 * <li>13 bytes DTLS record header</li>
	 * </ol>
	 * 25 bytes in total.
	 * 
	 * @since 3.0 (moved from {@link DTLSSession})
	 */
	public static final int DTLS_HANDSHAKE_HEADER_LENGTH = RECORD_HEADER_BYTES
			+ HandshakeMessage.MESSAGE_HEADER_LENGTH_BYTES;
	/**
	 * The maximum plaintext fragment size for TLS 1.2
	 * 
	 * @since 3.2
	 */
	public static final int DTLS_MAX_PLAINTEXT_FRAGMENT_LENGTH = 16384; // 2^14

	public static final long MAX_SEQUENCE_NO = 281474976710655L; // 2^48 - 1

	/**
	 * Sequence number placeholder for CID records.
	 * 
	 * @since 3.0
	 */
	private static final byte[] SEQUENCE_NUMBER_PLACEHOLDER = { -1, -1, -1, -1, -1, -1, -1, -1 };

	/** The higher-level protocol used to process the enclosed fragment */
	private ContentType type;

	/**
	 * The version of the protocol being employed. DTLS version 1.2 uses { 254, 253 }
	 */
	private final ProtocolVersion version;

	/** A counter value that is incremented on every cipher state change */
	private final int epoch;

	/** The sequence number for this record */
	private final long sequenceNumber;
	/**
	 * Receive time in uptime nanoseconds.
	 * 
	 * {@link ClockUtil#nanoRealtime()}
	 */
	private final long receiveNanos;
	/**
	 * Record follow other record in datagram.
	 * 
	 * Used to analyze construction of handshake.
	 * 
	 * @since 2.4
	 */
	private final boolean followUpRecord;
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
	/**
	 * Use deprecated MAC calculation.
	 * 
	 * @since 3.0
	 */
	private boolean useDeprecatedMac;

	/** Padding to be used with cid */
	private int padding;

	/** The peer address. */
	private InetSocketAddress peerAddress;

	/** The router address. */
	private InetSocketAddress router;

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
	 * @param receiveNanos uptime nanoseconds of receiving this record
	 * @param followUpRecord record follows up other record in same datagram
	 * @throws IllegalArgumentException if the given sequence number is longer
	 *             than 48 bits or less than 0. Or the given epoch is less than 0.
	 * @throws NullPointerException if the given type, protocol version,
	 *             or fragment bytes is {@code null}.
	 */
	Record(ContentType type, ProtocolVersion version, int epoch, long sequenceNumber, ConnectionId connectionId,
			byte[] fragmentBytes, long receiveNanos, boolean followUpRecord) {
		this(version, epoch, sequenceNumber, receiveNanos, followUpRecord);
		if (type == null) {
			throw new NullPointerException("Type must not be null");
		} else if (fragmentBytes == null) {
			throw new NullPointerException("Fragment bytes must not be null");
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
	 * to create a {@code Record} containing an un-encrypted fragment, use
	 * the {@link #Record(ContentType, ProtocolVersion, long, DTLSMessage)}
	 * constructor.
	 * 
	 * @param type the type of the record's payload. The new record type
	 *            {@link ContentType#TLS12_CID} is not supported directly.
	 *            Provide the inner type and {@code true} for the parameter cid
	 * @param epoch the epoch
	 * @param fragment the payload
	 * @param context the dtsl-context to determine the current write state from
	 * @param cid if {@code true} use write connection id from provided session.
	 *            Otherwise use {@code null} as connection id
	 * @param pad if cid is enabled, pad could be used to add that number of
	 *            zero-bytes as padding to the payload to obfuscate the payload
	 *            length.
	 * @throws IllegalStateException if the context sequence number is longer
	 *             than 48 bits.
	 * @throws IllegalArgumentException if the context sequence number is less
	 *             than 0, the given epoch is less than 0, the provided type is
	 *             not supported or the fragment could not be converted into
	 *             bytes. Or the provided session doesn't have a peer address.
	 * @throws NullPointerException if the given type, fragment or session is
	 *             {@code null}.
	 * @throws GeneralSecurityException if the message could not be encrypted,
	 *             e.g. because the JVM does not support the negotiated cipher
	 *             suite's cipher algorithm
	 * @since 3.0 (removed parameter sequenceNumber)
	 */
	public Record(ContentType type, int epoch, DTLSMessage fragment, DTLSContext context, boolean cid, int pad)
			throws GeneralSecurityException {
		this(ProtocolVersion.VERSION_DTLS_1_2, epoch,
				(context == null || epoch < 0) ? 0 : context.getNextSequenceNumber(epoch), 0, false);
		if (fragment == null) {
			throw new NullPointerException("Fragment must not be null");
		} else if (context == null) {
			throw new NullPointerException("Context must not be null");
		}
		setType(type);
		if (cid) {
			this.connectionId = context.getWriteConnectionId();
			// deprecated CID comes with the deprecated MAC calculation
			this.useDeprecatedMac = context.useDeprecatedCid();
			this.padding = pad;
		}
		setEncodedFragment(context.getWriteState(epoch), fragment);
		if (fragmentBytes == null) {
			throw new IllegalArgumentException("Fragment missing encoded bytes!");
		}
	}

	/**
	 * Creates an outbound record representing a {@link DTLSMessage} as its payload.
	 * 
	 * The payload will be sent un-encrypted using epoch 0.
	 * 
	 * @param type the type of the record's payload. The new record type
	 *            {@link ContentType#TLS12_CID} is not supported.
	 * @param version the version
	 * @param sequenceNumber the 48-bit sequence number
	 * @param fragment the payload to send
	 * @throws IllegalArgumentException if the given sequence number is longer
	 *             than 48 bits or less than 0, the given epoch is less than
	 *             0, or the fragment could not be converted into bytes.
	 * @throws NullPointerException if the given type, or fragment is {@code null}.
	 */
	public Record(ContentType type, ProtocolVersion version, long sequenceNumber, DTLSMessage fragment) {
		this(version, 0, sequenceNumber, 0, false);
		if (fragment == null) {
			throw new NullPointerException("Fragment must not be null");
		}
		setType(type);
		this.fragment = fragment;
		this.fragmentBytes = fragment.toByteArray();
		if (fragmentBytes == null) {
			throw new IllegalArgumentException("Fragment missing encoded bytes!");
		}
	}

	private Record(ProtocolVersion version, int epoch, long sequenceNumber, long receiveNanos, boolean followUpRecord) {
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
		this.followUpRecord = followUpRecord;
	}

	/**
	 * Set record's address.
	 * 
	 * Either source or destination.
	 * 
	 * @param peerAddress peer's address
	 * @param router router address, {@code null}, if not used.
	 * @throws IllegalStateException if a peer's address was already set.
	 * @throws NullPointerException if the provided peer's address is
	 *             {@code null}.
	 * @since 3.0
	 */
	public void setAddress(InetSocketAddress peerAddress, InetSocketAddress router) {
		if (this.peerAddress != null) {
			throw new IllegalStateException("Peer's address already available!");
		}
		if (peerAddress == null) {
			throw new NullPointerException("Peer's address must not be null!");
		}
		this.peerAddress = peerAddress;
		this.router = router;
	}

	/**
	 * Encodes this record into its corresponding <em>DTLSCiphertext</em> structure.
	 * 
	 * @return a byte array containing the <em>DTLSCiphertext</em> structure
	 */
	public byte[] toByteArray() {
		final boolean useCid = useConnectionId();
		int length = fragmentBytes.length + RECORD_HEADER_BYTES;
		if (useCid) {
			length += connectionId.length();
		}
		DatagramWriter writer = new DatagramWriter(length);

		if (useCid) {
			writer.write(ContentType.TLS12_CID.getCode(), CONTENT_TYPE_BITS);
		} else {
			writer.write(type.getCode(), CONTENT_TYPE_BITS);
		}

		writer.write(version.getMajor(), VERSION_BITS);
		writer.write(version.getMinor(), VERSION_BITS);

		writer.write(epoch, EPOCH_BITS);
		writer.writeLong(sequenceNumber, SEQUENCE_NUMBER_BITS);
		if (useCid) {
			writer.writeBytes(connectionId.getBytes());
		}
		writer.write(fragmentBytes.length, LENGTH_BITS);
		writer.writeBytes(fragmentBytes);

		return writer.toByteArray();
	}

	public int size() {
		int cid = useConnectionId() ? connectionId.length() : 0;
		return RECORD_HEADER_BYTES + cid + getFragmentLength();
	}

	/**
	 * Parses a sequence of <em>DTLSCiphertext</em> structures into {@code Record} instances.
	 * 
	 * The binary representation is expected to comply with the <em>DTLSCiphertext</em> structure
	 * defined in <a href="https://tools.ietf.org/html/rfc6347#section-4.3.1" target="_blank">RFC6347, Section 4.3.1</a>.
	 * 
	 * @param reader a reader with the raw binary representation containing one or more DTLSCiphertext structures
	 * @param cidGenerator the connection id generator. May be {@code null}.
	 * @param receiveNanos uptime nanoseconds of receiving this record
	 * @return the {@code Record} instances
	 * @throws NullPointerException if either one of the reader or peer address is {@code null}
	 * @since 2.4
	 */
	public static List<Record> fromReader(DatagramReader reader, ConnectionIdGenerator cidGenerator, long receiveNanos) {
		if (reader == null) {
			throw new NullPointerException("Reader must not be null");
		}

		int datagramLength = reader.bitsLeft() / Byte.SIZE;

		List<Record> records = new ArrayList<Record>();

		while (reader.bytesAvailable()) {

			if (reader.bitsLeft() < RECORD_HEADER_BITS) {
				LOGGER.debug("Received truncated DTLS record(s). Discarding ...");
				return records;
			}

			int type = reader.read(CONTENT_TYPE_BITS);
			int major = reader.read(VERSION_BITS);
			int minor = reader.read(VERSION_BITS);
			ProtocolVersion version = ProtocolVersion.valueOf(major, minor);

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
						LOGGER.debug("Received TLS_CID record, failed to read cid. Discarding ...", ex);
						return records;
					}
				} else {
					LOGGER.debug("Received TLS_CID record, but cid is not used. Discarding ...");
					return records;
				}
			}
			int length = reader.read(LENGTH_BITS);
			int left = reader.bitsLeft() / Byte.SIZE;
			if (left < length) {
				LOGGER.debug(
						"Received truncated DTLS record(s) ({} bytes, but only {} available). {} records, {} bytes. Discarding ...",
						length, left, records.size(), datagramLength);
				return records;
			}

			// delay decryption/interpretation of fragment
			byte[] fragmentBytes = reader.readBytes(length);

			ContentType contentType = ContentType.getTypeByValue(type);
			if (contentType == null) {
				LOGGER.debug("Received DTLS record of unsupported type [{}]. Discarding ...", type);
			} else {
				records.add(new Record(contentType, version, epoch, sequenceNumber, connectionId, fragmentBytes,
						receiveNanos, !records.isEmpty()));
			}
		}

		return records;
	}

	/**
	 * Read the connection id.
	 * 
	 * @param reader reader with the raw received record.
	 * @param cidGenerator cid generator.
	 * @return connection, or {@code null}, if not available.
	 * @throws NullPointerException if either reader or cid generator is
	 *             {@code null}.
	 * @throws IllegalArgumentException if the cid generator doesn't use cid or
	 *             the record is too short.
	 * @since 2.5
	 */
	public static ConnectionId readConnectionIdFromReader(DatagramReader reader, ConnectionIdGenerator cidGenerator) {
		if (reader == null) {
			throw new NullPointerException("Reader must not be null");
		} else if (cidGenerator == null) {
			throw new NullPointerException("CID generator must not be null");
		} else if (!cidGenerator.useConnectionId()) {
			throw new IllegalArgumentException("CID generator must use CID");
		} else if (reader.bitsLeft() < RECORD_HEADER_BITS) {
			throw new IllegalArgumentException("Record too small for DTLS header");
		}

		int type = reader.read(CONTENT_TYPE_BITS);
		if (type != ContentType.TLS12_CID.getCode()) {
			return null;
		}
		reader.skip(VERSION_BITS + VERSION_BITS + EPOCH_BITS + SEQUENCE_NUMBER_BITS);
		ConnectionId connectionId = cidGenerator.read(reader);
		int length = reader.read(LENGTH_BITS);
		int left = reader.bitsLeft() / Byte.SIZE;
		if (left < length) {
			throw new IllegalArgumentException("Record too small for DTLS length " + length);
		}

		return connectionId;
	}

	/**
	 * Generates the explicit part of the nonce to be used with the AEAD Cipher.
	 * 
	 * <a href="https://tools.ietf.org/html/rfc6655#section-3" target="_blank">RFC6655, Section 3</a>
	 * encourages the use of the session's 16bit epoch value concatenated
	 * with a monotonically increasing 48bit sequence number as the explicit nonce. 
	 * 
	 * @param writer writer for nonce
	 */
	protected void writeExplicitNonce(DatagramWriter writer) {
		//TODO: re-factor to use simple byte array manipulation instead of using bit-based DatagramWriter
		writer.write(epoch, EPOCH_BITS);
		writer.writeLong(sequenceNumber, SEQUENCE_NUMBER_BITS);
	}

	/**
	 * Generates the additional authentication data.
	 * 
	 * According {@link #useConnectionId()} and {@link #useDeprecatedMac}, use
	 * {@link #generateAdditionalDataRfc6347(int)},
	 * {@link #generateAdditionalDataCidDeprecated(int)}, or
	 * {@link #generateAdditionalDataCid(int)}.
	 * 
	 * @param length length of the data to be authenticated
	 * @return the additional authentication data.
	 */
	protected byte[] generateAdditionalData(int length) {
		if (!useConnectionId()) {
			return generateAdditionalDataRfc6347(length);
		} else if (useDeprecatedMac) {
			return generateAdditionalDataCidDeprecated(length);
		} else {
			return generateAdditionalDataCid(length);
		}
	}

	/**
	 * Generate the additional authentication data according
	 * <a href= "https://www.rfc-editor.org/rfc/rfc9146.html#section-5" target
	 * ="_blank">RFC 9146, Connection Identifier for DTLS 1.2, 5. Record Payload
	 * Protection</a>
	 * 
	 * <pre>
	 * additional_data = seq_num_placeholder + tls_cid + connection_id_length
	 * 		+ tls_cid + TLSCompressed.version + epoch + sequence_number +
	 * 		+ connection_id + TLSCompressed.length;
	 * </pre>
	 * 
	 * where "+" denotes concatenation and the connection_id_length is encoded
	 * in one uint8 byte.
	 * 
	 * @param length length of the data to be authenticated
	 * @return the additional authentication data.
	 * @since 3.0
	 */
	protected byte[] generateAdditionalDataCid(int length) {
		DatagramWriter writer = new DatagramWriter(RECORD_HEADER_BYTES + connectionId.length() + 1 + 1 + 8);

		writer.writeBytes(SEQUENCE_NUMBER_PLACEHOLDER);
		writer.write(ContentType.TLS12_CID.getCode(), CONTENT_TYPE_BITS);
		writer.write(connectionId.length(), CID_LENGTH_BITS);
		writer.write(ContentType.TLS12_CID.getCode(), CONTENT_TYPE_BITS);
		writer.write(version.getMajor(), VERSION_BITS);
		writer.write(version.getMinor(), VERSION_BITS);
		writer.write(epoch, EPOCH_BITS);
		writer.writeLong(sequenceNumber, SEQUENCE_NUMBER_BITS);
		writer.writeBytes(connectionId.getBytes());
		writer.write(length, LENGTH_BITS);

		return writer.toByteArray();
	}

	/**
	 * Generates the additional authentication data according <a href=
	 * "https://datatracker.ietf.org/doc/html/draft-ietf-tls-dtls-connection-id-08#section-5"
	 * target= "_blank">draft dtls connection id (up to Version 8), 5. Record
	 * Payload Protection</a>:
	 * 
	 * <pre>
	 * additional_data = epoch + seq_num + tls_cid + TLSCompressed.version + connection_id + connection_id_length
	 * 		+ TLSCompressed.length;
	 * </pre>
	 * 
	 * where "+" denotes concatenation and the connection_id_length is encoded
	 * in one uint8 byte.
	 * 
	 * @param length length of the data to be authenticated
	 * @return the additional authentication data.
	 */
	protected byte[] generateAdditionalDataCidDeprecated(int length) {
		DatagramWriter writer = new DatagramWriter(RECORD_HEADER_BYTES + connectionId.length() + 1);

		writer.write(epoch, EPOCH_BITS);
		writer.writeLong(sequenceNumber, SEQUENCE_NUMBER_BITS);

		writer.write(ContentType.TLS12_CID.getCode(), CONTENT_TYPE_BITS);
		writer.write(version.getMajor(), VERSION_BITS);
		writer.write(version.getMinor(), VERSION_BITS);
		writer.writeBytes(connectionId.getBytes());
		writer.write(connectionId.length(), CID_LENGTH_BITS);
		writer.write(length, LENGTH_BITS);

		return writer.toByteArray();
	}

	/**
	 * See <a href="https://tools.ietf.org/html/rfc5246#section-6.2.3.3" target=
	 * "_blank">RFC 5246</a> and
	 * <a href="https://tools.ietf.org/html/rfc6347#section-4.1.2.1" target=
	 * "_blank">RFC 6347</a>:
	 * 
	 * <pre>
	 * additional_data = seq_num + TLSCompressed.type + TLSCompressed.version + TLSCompressed.length;
	 * </pre>
	 * 
	 * where "+" denotes concatenation.
	 * 
	 * @param length length of the data to be authenticated
	 * @return the additional authentication data.
	 */
	protected byte[] generateAdditionalDataRfc6347(int length) {
		DatagramWriter writer = new DatagramWriter(RECORD_HEADER_BYTES);

		writer.write(epoch, EPOCH_BITS);
		writer.writeLong(sequenceNumber, SEQUENCE_NUMBER_BITS);

		writer.write(type.getCode(), CONTENT_TYPE_BITS);
		writer.write(version.getMajor(), VERSION_BITS);
		writer.write(version.getMinor(), VERSION_BITS);
		writer.write(length, LENGTH_BITS);

		return writer.toByteArray();
	}

	/**
	 * Get follow-up-record marker for received record.
	 * 
	 * @return {@code true}, if record follows up an other record in the same
	 *         datagram, {@code false}, otherwise.
	 * @since 2.4
	 */
	public boolean isFollowUpRecord() {
		return followUpRecord;
	}

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

	/**
	 * Check, if record is decoded.
	 * 
	 * @return {@code true}, if records is decode, {@code false}, otherwise.
	 * @since 2.4
	 */
	public boolean isDecoded() {
		return fragment != null;
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
	 * Gets the length of the fragment contained in this record in bytes.
	 * <p>
	 * The overall length of this record's <em>DTLSCiphertext</em>
	 * representation is thus {@code Record.length} + 13 (DTLS record headers) + CID
	 * bytes.
	 * 
	 * @return the fragment length excluding record headers
	 */
	public int getFragmentLength() {
		return fragmentBytes.length;
	}

	/**
	 * Get peer address.
	 * 
	 * @return peer address
	 */
	public InetSocketAddress getPeerAddress() {
		return peerAddress;
	}

	/**
	 * Get router address.
	 * 
	 * @return router address. {@code null}, if no router is used.
	 */
	public InetSocketAddress getRouter() {
		return router;
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
	 * For incoming records, the fragment is only available after
	 * {@link #decodeFragment(DTLSConnectionState)}.
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
	 * Set usage of deprecated MAC.
	 * 
	 * @param useDeprecatedMac {@code true}, if the deprecated MAC calculation
	 *            is used, {@code false}, otherwise.
	 * @since 3.0
	 */
	public void setDeprecatedMac(boolean useDeprecatedMac) {
		this.useDeprecatedMac = useDeprecatedMac;
	}

	/**
	 * Decode the object representation of this record's
	 * <em>DTLSPlaintext.fragment</em>.
	 * 
	 * If the record uses the new record type {@link ContentType#TLS12_CID} the
	 * {@link #type} is updated with the type of the inner plaintext.
	 * 
	 * If CID is used, {@link #setDeprecatedMac(boolean)} must be called before
	 * decoding a fragment.
	 * 
	 * @param readState read state of the epoch for incoming messages
	 * @throws InvalidMacException if message authentication failed
	 * @throws GeneralSecurityException if de-cryption fails, e.g. because the
	 *             JVM does not support the negotiated cipher algorithm, or
	 *             decoding of the inner plain text of
	 *             {@link ContentType#TLS12_CID} fails.
	 * @throws HandshakeException if the TLSPlaintext.fragment could not be
	 *             parsed into a valid handshake message
	 */
	public void decodeFragment(DTLSConnectionState readState) throws GeneralSecurityException, HandshakeException {

		if (fragment != null) {
			LOGGER.error("DTLS read state already applied!");
			throw new IllegalArgumentException("DTLS read state already applied!");
		}

		ContentType actualType = type;
		// decide, which type of fragment need de-cryption
		byte[] decryptedMessage = readState.decrypt(this, fragmentBytes);

		if (ContentType.TLS12_CID == type) {
			int index = decryptedMessage.length - 1;
			while (index >= 0 && decryptedMessage[index] == 0) {
				--index;
			}
			if (index < 0) {
				throw new GeneralSecurityException("no inner type!");
			}
			int typeCode = decryptedMessage[index];
			actualType = ContentType.getTypeByValue(typeCode);
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
			fragment = AlertMessage.fromByteArray(decryptedMessage);
			break;

		case APPLICATION_DATA:
			// http://tools.ietf.org/html/rfc5246#section-7.2:
			// "Like other messages, alert messages are encrypted and
			// compressed, as specified by the current connection state."
			fragment = ApplicationMessage.fromByteArray(decryptedMessage);
			break;

		case CHANGE_CIPHER_SPEC:
			// http://tools.ietf.org/html/rfc5246#section-7.1:
			// "is encrypted and compressed under the current (not the pending)
			// connection state"
			fragment = ChangeCipherSpecMessage.fromByteArray(decryptedMessage);
			break;

		case HANDSHAKE:

			fragment = HandshakeMessage.fromByteArray(decryptedMessage);
			break;

		default:
			LOGGER.debug("Cannot decrypt message of unsupported type [{}]", type);
		}
		type = actualType;
	}

	/**
	 * Sets the DTLS fragment. At the same time, it creates the corresponding
	 * raw binary representation and encrypts it if necessary (depending on
	 * current connection state). If cid is used, create also the "inner plain
	 * text" containing the payload, the original record type, and optional
	 * padding with zeros before encryption.
	 * 
	 * @param outgoingWriteState write state to be applied to fragment
	 * @param fragment the DTLS fragment
	 * @throws GeneralSecurityException if the message could not be encrypted,
	 *             e.g. because the JVM does not support the negotiated cipher
	 *             suite's cipher algorithm
	 * @throws NullPointerException if {@link DTLSMessage#toByteArray()} return
	 *             {@code null}.
	 * @see #useConnectionId()
	 */
	private void setEncodedFragment(DTLSConnectionState outgoingWriteState, DTLSMessage fragment)
			throws GeneralSecurityException {
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
	 * "https://datatracker.ietf.org/doc/draft-ietf-tls-dtls-connection-id/">Draft
	 * dtls-connection-id</a> 2019-feb-18: the last discussion agreement is NOT
	 * to use a empty CID for tls_cid records.
	 * 
	 * @return {@code true}, if a none empty cid is used.
	 * @see #Record(ContentType, int, DTLSMessage, DTLSContext, boolean, int)
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
		sb.append("==[ DTLS Record ]==============================================").append(StringUtil.lineSeparator());
		sb.append("Content Type: ").append(type).append(StringUtil.lineSeparator());
		sb.append("Peer address: ").append(getPeerAddress()).append(StringUtil.lineSeparator());
		sb.append("Version: ").append(version.getMajor()).append(", ")
				.append(version.getMinor()).append(StringUtil.lineSeparator());
		sb.append("Epoch: ").append(epoch).append(StringUtil.lineSeparator());
		sb.append("Sequence Number: ").append(sequenceNumber).append(StringUtil.lineSeparator());
		if (connectionId != null) {
			sb.append("connection id: ").append(connectionId.getAsString()).append(StringUtil.lineSeparator());
		}
		sb.append("Length: ").append(fragmentBytes.length).append(" bytes").append(StringUtil.lineSeparator());
		sb.append("Fragment:").append(StringUtil.lineSeparator());
		if (fragment != null) {
			sb.append(fragment.toString(1));
		} else {
			sb.append("fragment is not decrypted yet").append(StringUtil.lineSeparator());
		}
		sb.append("===============================================================").append(StringUtil.lineSeparator());

		return sb.toString();
	}

}
