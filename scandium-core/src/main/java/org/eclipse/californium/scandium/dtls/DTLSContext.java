/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - split from DTLSSession
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.InvalidKeyException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.SerializationUtil;
import org.eclipse.californium.elements.util.SerializationUtil.SupportedVersions;
import org.eclipse.californium.elements.util.SerializationUtil.SupportedVersionsMatcher;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.util.SecretIvParameterSpec;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a DTLS context between two peers. Keeps track of the current and
 * pending read/write states, the current epoch and sequence number, etc.
 * Contains the keys and the {@link DTLSSession}.
 * 
 * @since 3.0
 */
public final class DTLSContext implements Destroyable {

	private static final Logger LOGGER = LoggerFactory.getLogger(DTLSContext.class);
	private static final long RECEIVE_WINDOW_SIZE = 64;

	/**
	 * Use deprecated MAC for CID.
	 * 
	 * @since 3.0
	 */
	private boolean useDeprecatedCid;
	/**
	 * Connection id used for all outbound records.
	 */
	private ConnectionId writeConnectionId = null;
	/**
	 * Connection id used for all inbound records.
	 */
	private ConnectionId readConnectionId = null;

	/**
	 * The <em>current read state</em> used for processing all inbound records.
	 */
	private DTLSConnectionState readState = DTLSConnectionState.NULL;

	/**
	 * The <em>current write state</em> used for processing all outbound
	 * records.
	 */
	private DTLSConnectionState writeState = DTLSConnectionState.NULL;

	/**
	 * Write key for cluster internal communication.
	 */
	private SecretKey clusterWriteMacKey = null;
	/**
	 * Read key for cluster internal communication.
	 */
	private SecretKey clusterReadMacKey = null;

	/**
	 * Indicates, if support for key material export is enabled.
	 * 
	 * @see DtlsConfig#DTLS_SUPPORT_KEY_MATERIAL_EXPORT
	 * @since 3.10
	 */
	private final boolean supportExport;
	/**
	 * Client random.
	 * 
	 * Only available, if {@link DtlsConfig#DTLS_SUPPORT_KEY_MATERIAL_EXPORT} is
	 * enabled.
	 * 
	 * @since 3.10
	 */
	private Random clientRandom;
	/**
	 * Server random.
	 * 
	 * Only available, if {@link DtlsConfig#DTLS_SUPPORT_KEY_MATERIAL_EXPORT} is
	 * enabled.
	 * 
	 * @since 3.10
	 */
	private Random serverRandom;

	/**
	 * The current read epoch, incremented with every CHANGE_CIPHER_SPEC message
	 * received
	 */
	private int readEpoch = 0;
	/**
	 * The current read epoch, incremented with every CHANGE_CIPHER_SPEC message
	 * sent
	 */
	private int writeEpoch = 0;
	/**
	 * The effective fragment size.
	 */
	private int effectiveMaxMessageSize;

	/**
	 * The next record sequence number per epoch.
	 */
	// We only need 2 values as we do not support DTLS re-negotiation.
	private long[] sequenceNumbers = new long[2];

	/**
	 * Save close_notify
	 */
	private int readEpochClosed;
	private long readSequenceNumberClosed;
	private boolean markedAsclosed;

	private volatile long receiveWindowUpperCurrent = -1;
	private volatile long receiveWindowLowerBoundary = 0;
	private volatile long receivedRecordsVector = 0;

	private volatile long macErrors = 0;

	private final long handshakeTime;
	private final DTLSSession session;

	/**
	 * Creates a new DTLS context initialized with a given record sequence
	 * number.
	 *
	 * @param initialRecordSequenceNo the initial record sequence number to
	 *            start from in epoch 0. When starting a new handshake with a
	 *            client that has successfully exchanged a cookie with the
	 *            server, the sequence number to use in the SERVER_HELLO record
	 *            MUST be the same as the one from the successfully validated
	 *            CLIENT_HELLO record (see
	 *            <a href="https://tools.ietf.org/html/rfc6347#section-4.2.1"
	 *            target="_blank"> section 4.2.1 of RFC 6347 (DTLS 1.2)</a> for
	 *            details)
	 * @throws IllegalArgumentException if sequence number is out of the valid
	 *             range {@code [0...2^48)}.
	 *             @deprecated use {@link #DTLSContext(long, boolean)} instead.
	 */
	@Deprecated
	DTLSContext(long initialRecordSequenceNo) {
		this(initialRecordSequenceNo, false);
	}

	/**
	 * Creates a new DTLS context initialized with a given record sequence
	 * number.
	 *
	 * @param initialRecordSequenceNo the initial record sequence number to
	 *            start from in epoch 0. When starting a new handshake with a
	 *            client that has successfully exchanged a cookie with the
	 *            server, the sequence number to use in the SERVER_HELLO record
	 *            MUST be the same as the one from the successfully validated
	 *            CLIENT_HELLO record (see
	 *            <a href="https://tools.ietf.org/html/rfc6347#section-4.2.1"
	 *            target="_blank"> section 4.2.1 of RFC 6347 (DTLS 1.2)</a> for
	 *            details)
	 * @param supportExport {@code true}, if
	 *            {@link DtlsConfig#DTLS_SUPPORT_KEY_MATERIAL_EXPORT} is
	 *            enabled.
	 * @throws IllegalArgumentException if sequence number is out of the valid
	 *             range {@code [0...2^48)}.
	 * @since 3.10
	 */
	DTLSContext(long initialRecordSequenceNo, boolean supportExport) {
		if (initialRecordSequenceNo < 0 || initialRecordSequenceNo > Record.MAX_SEQUENCE_NO) {
			throw new IllegalArgumentException("Initial sequence number must be greater than 0 and less than 2^48");
		}
		this.session = new DTLSSession();
		this.handshakeTime = System.currentTimeMillis();
		this.sequenceNumbers[0] = initialRecordSequenceNo;
		this.supportExport = supportExport;
	}

	@Override
	public void destroy() throws DestroyFailedException {
		SecretUtil.destroy(session);
		SecretUtil.destroy(clusterWriteMacKey);
		clusterWriteMacKey = null;
		SecretUtil.destroy(clusterReadMacKey);
		clusterReadMacKey = null;
		if (readState != DTLSConnectionState.NULL) {
			readState.destroy();
			readState = DTLSConnectionState.NULL;
		}
		if (writeState != DTLSConnectionState.NULL) {
			writeState.destroy();
			writeState = DTLSConnectionState.NULL;
		}
	}

	@Override
	public boolean isDestroyed() {
		return SecretUtil.isDestroyed(session) && SecretUtil.isDestroyed(readState)
				&& SecretUtil.isDestroyed(writeState) && SecretUtil.isDestroyed(clusterReadMacKey)
				&& SecretUtil.isDestroyed(clusterWriteMacKey);
	}

	/**
	 * Get the DTLS session.
	 * 
	 * @return the DTLS session
	 */
	public DTLSSession getSession() {
		return session;
	}

	/**
	 * Use deprecated definitions for extension ID and MAC calculation.
	 * 
	 * @return {@code true}, if the deprecated extension ID {@code 53} along
	 *         with the deprecated MAC calculation is used, {@code false},
	 *         otherwise.
	 * @since 3.0
	 */
	public boolean useDeprecatedCid() {
		return useDeprecatedCid;
	}

	/**
	 * Set usage of deprecated definitions for extension ID and MAC calculation.
	 * 
	 * @param useDeprecatedCid {@code true}, if the deprecated extension ID
	 *            {@code 53} along with the deprecated MAC calculation is used,
	 *            {@code false}, otherwise.
	 * @since 3.0
	 */
	void setDeprecatedCid(boolean useDeprecatedCid) {
		this.useDeprecatedCid = useDeprecatedCid;
	}

	/**
	 * Get connection id for outbound records.
	 * 
	 * @return connection id for outbound records. {@code null}, if connection
	 *         id is not used by other peer
	 */
	public ConnectionId getWriteConnectionId() {
		return writeConnectionId;
	}

	/**
	 * Set connection id for outbound records.
	 * 
	 * @param connectionId connection id for outbound records
	 */
	void setWriteConnectionId(ConnectionId connectionId) {
		this.writeConnectionId = connectionId;
	}

	/**
	 * Get connection id for inbound records.
	 * 
	 * @return connection id for inbound records. {@code null}, if connection id
	 *         is not used for other peer
	 */
	public ConnectionId getReadConnectionId() {
		return readConnectionId;
	}

	/**
	 * Set connection id for inbound records.
	 * 
	 * @param connectionId connection id for inbound records
	 */
	void setReadConnectionId(ConnectionId connectionId) {
		this.readConnectionId = connectionId;
	}

	/**
	 * Set mac-keys for cluster communication
	 * 
	 * @param clusterWriteMacKey write mac-key
	 * @param clusterReadMacKey read mac-key
	 */
	void setClusterMacKeys(SecretKey clusterWriteMacKey, SecretKey clusterReadMacKey) {
		this.clusterWriteMacKey = SecretUtil.create(clusterWriteMacKey);
		this.clusterReadMacKey = SecretUtil.create(clusterReadMacKey);
	}

	/**
	 * Get thread local cluster write MAC.
	 * 
	 * Initialize the MAC with the {@link #clusterWriteMacKey}.
	 * 
	 * @return thread local cluster write MAC, or {@code null}, if not
	 *         available.
	 */
	public Mac getThreadLocalClusterWriteMac() {
		if (clusterWriteMacKey != null) {
			try {
				Mac mac = session.getCipherSuite().getThreadLocalPseudoRandomFunctionMac();
				mac.init(clusterWriteMacKey);
				return mac;
			} catch (InvalidKeyException e) {
				LOGGER.info("cluster write MAC error", e);
			}
		}
		return null;
	}

	/**
	 * Get thread local cluster read MAC.
	 * 
	 * Initialize the MAC with the {@link #clusterReadMacKey}.
	 * 
	 * @return thread local cluster read MAC, or {@code null}, if not available.
	 */
	public Mac getThreadLocalClusterReadMac() {
		if (clusterReadMacKey != null) {
			try {
				Mac mac = session.getCipherSuite().getThreadLocalPseudoRandomFunctionMac();
				mac.init(clusterReadMacKey);
				return mac;
			} catch (InvalidKeyException e) {
				LOGGER.info("cluster read MAC error!", e);
			}
		}
		return null;
	}

	/**
	 * Set client- and server-random.
	 * 
	 * Only applied, if {@link DtlsConfig#DTLS_SUPPORT_KEY_MATERIAL_EXPORT} is
	 * enabled.
	 * 
	 * @param clientRandom client random
	 * @param serverRandom server random
	 * @since 3.10
	 */
	void setRandoms(Random clientRandom, Random serverRandom) {
		if (supportExport) {
			this.clientRandom = clientRandom;
			this.serverRandom = serverRandom;
		}
	}

	/**
	 * Calculate the pseudo random function for exporter as defined in
	 * <a href="https://tools.ietf.org/html/rfc5246#section-5" target=
	 * "_blank">RFC 5246</a> and
	 * <a href="https://tools.ietf.org/html/rfc5705#section-4" target=
	 * "_blank">RFC 5705</a>.
	 *
	 * In order to use this function,
	 * {@link DtlsConfig#DTLS_SUPPORT_KEY_MATERIAL_EXPORT} must be enabled.
	 * 
	 * @param label label to use
	 * @param context context, or {@code null}, if no context is used.
	 * @param length length of the key.
	 * @return calculated pseudo random for exporter
	 * @throws IllegalArgumentException if label is not allowed for exporter
	 * @throws IllegalStateException if DTLS_SUPPORT_KEY_MATERIAL_EXPORT is not
	 *             enabled or the random is missing.
	 * @since 3.10
	 */
	public byte[] exportKeyMaterial(byte[] label, byte[] context, int length) {
		if (!supportExport) {
			throw new IllegalStateException("DTLS_SUPPORT_KEY_MATERIAL_EXPORT not enabled!");
		}
		if (clientRandom == null || serverRandom == null) {
			throw new IllegalStateException("Random missing!");
		}
		byte[] seed = Bytes.concatenate(clientRandom, serverRandom);
		if (context != null) {
			DatagramWriter writer = new DatagramWriter(seed.length + context.length + 2);
			writer.writeBytes(seed);
			writer.write(context.length, Short.SIZE);
			writer.writeBytes(context);
			seed = writer.toByteArray();
		}
		return session.exportKeyMaterial(label, seed, length);
	}

	/**
	 * System time tag of last handshake.
	 * 
	 * @return system time in milliseconds as string of the last handshake
	 */
	public long getLastHandshakeTime() {
		return handshakeTime;
	}

	/**
	 * Add entries for writing.
	 * 
	 * @param attributes attributes to add the entries
	 */
	public void addWriteEndpointContext(MapBasedEndpointContext.Attributes attributes) {
		addEndpointContext(attributes, writeEpoch);
	}

	/**
	 * Add entries for reading.
	 * 
	 * @param attributes attributes to add the entries
	 */
	public void addReadEndpointContext(MapBasedEndpointContext.Attributes attributes) {
		addEndpointContext(attributes, readEpoch);
	}

	/**
	 * Add entries for the epoch.
	 * 
	 * @param attributes attributes to add the entries
	 * @param epoch epoch of attributes
	 */
	private void addEndpointContext(MapBasedEndpointContext.Attributes attributes, int epoch) {
		session.addEndpointContext(attributes);
		attributes.add(DtlsEndpointContext.KEY_EPOCH, epoch);
		attributes.add(DtlsEndpointContext.KEY_HANDSHAKE_TIMESTAMP, handshakeTime);
		if (writeConnectionId != null && readConnectionId != null) {
			attributes.add(DtlsEndpointContext.KEY_READ_CONNECTION_ID, readConnectionId);
			attributes.add(DtlsEndpointContext.KEY_WRITE_CONNECTION_ID, writeConnectionId);
		}
		if (effectiveMaxMessageSize > 0) {
			attributes.add(DtlsEndpointContext.KEY_MESSAGE_SIZE_LIMIT, effectiveMaxMessageSize);
		}
	}

	/**
	 * Gets this DTLS context's current write epoch.
	 * 
	 * @return The write epoch.
	 */
	public int getWriteEpoch() {
		return writeEpoch;
	}

	// tests only, currently not used
	void setWriteEpoch(int epoch) {
		if (epoch < 0) {
			throw new IllegalArgumentException("Write epoch must not be negative");
		} else {
			this.writeEpoch = epoch;
		}
	}

	/**
	 * Gets this DTLS context's current read epoch.
	 * 
	 * @return The read epoch.
	 */
	public int getReadEpoch() {
		return readEpoch;
	}

	void setReadEpoch(int epoch) {
		if (epoch < 0) {
			throw new IllegalArgumentException("Read epoch must not be negative");
		} else {
			resetReceiveWindow();
			this.readEpoch = epoch;
		}
	}

	void incrementReadEpoch() {
		resetReceiveWindow();
		this.readEpoch++;
	}

	private void incrementWriteEpoch() {
		this.writeEpoch++;
		// Sequence numbers are maintained separately for each epoch, with each
		// sequence_number initially being 0 for each epoch.
		this.sequenceNumbers[writeEpoch] = 0L;
	}

	/**
	 * Gets the smallest unused sequence number for outbound records for the
	 * current epoch.
	 * 
	 * @return the next sequence number
	 * @throws IllegalStateException if the maximum sequence number for the
	 *             epoch has been reached (2^48 - 1)
	 * @since 3.0 (renamed, was getSequenceNumber)
	 */
	public long getNextSequenceNumber() {
		return getNextSequenceNumber(writeEpoch);
	}

	/**
	 * Gets the smallest unused sequence number for outbound records for a given
	 * epoch.
	 * 
	 * @param epoch the epoch for which to get the sequence number
	 * @return the next sequence number
	 * @throws IllegalStateException if the maximum sequence number for the
	 *             epoch has been reached (2^48 - 1)
	 * @since 3.0 (renamed, was getSequenceNumber)
	 */
	public long getNextSequenceNumber(int epoch) {
		long sequenceNumber = this.sequenceNumbers[epoch];
		if (sequenceNumber <= Record.MAX_SEQUENCE_NO) {
			this.sequenceNumbers[epoch] = sequenceNumber + 1;
			return sequenceNumber;
		} else {
			// maximum sequence number has been reached
			// TODO force re-handshake with peer as mandated by DTLS spec
			// see section 4.1 of RFC 6347 (DTLS 1.2)
			throw new IllegalStateException("Maximum sequence number for epoch has been reached");
		}
	}

	/**
	 * Gets the current read state of the connection.
	 * <p>
	 * The information in the current read state is used to de-crypt messages
	 * received from a peer. See
	 * <a href="https://tools.ietf.org/html/rfc5246#section-6.1" target=
	 * "_blank"> RFC 5246 (TLS 1.2)</a> for details.
	 * <p>
	 * The cipher suite of the returned object will be
	 * {@link CipherSuite#TLS_NULL_WITH_NULL_NULL}, if the connection's crypto
	 * parameters have not yet been negotiated.
	 * 
	 * @return The current read state.
	 */
	public DTLSConnectionState getReadState() {
		return readState;
	}

	/**
	 * Create the current read state of the connection.
	 * 
	 * The information in the current read state is used to de-crypt messages
	 * received from a peer. See
	 * <a href="https://tools.ietf.org/html/rfc5246#section-6.1" target=
	 * "_blank"> RFC 5246 (TLS 1.2)</a> for details.
	 * 
	 * The <em>pending</em> read state becomes the <em>current</em> read state
	 * whenever a <em>CHANGE_CIPHER_SPEC</em> message is received from a peer
	 * during a handshake.
	 * 
	 * This method also increments the read epoch.
	 * 
	 * @param encryptionKey the secret key to use for decrypting message content
	 * @param iv the initialization vector to use for decrypting message content
	 * @param macKey the key to use for verifying message authentication codes
	 *            (MAC)
	 * @throws NullPointerException if any of the parameter used by the provided
	 *             cipher suite is {@code null}
	 */
	public void createReadState(SecretKey encryptionKey, SecretIvParameterSpec iv, SecretKey macKey) {
		DTLSConnectionState readState = DTLSConnectionState.create(session.getCipherSuite(),
				session.getCompressionMethod(), encryptionKey, iv, macKey);
		SecretUtil.destroy(this.readState);
		this.readState = readState;
		incrementReadEpoch();
		LOGGER.trace("Setting current read state to{}{}", StringUtil.lineSeparator(), readState);
	}

	/**
	 * Gets the name of the current read state's cipher suite.
	 * 
	 * @return the name.
	 */
	public String getReadStateCipher() {
		return readState.getCipherSuite().name();
	}

	/**
	 * Gets the current write state of the connection.
	 * <p>
	 * The information in the current write state is used to en-crypt messages
	 * sent to a peer. See
	 * <a href="https://tools.ietf.org/html/rfc5246#section-6.1" target=
	 * "_blank"> RFC 5246 (TLS 1.2)</a> for details.
	 * <p>
	 * The cipher suite of the returned object will be
	 * {@link CipherSuite#TLS_NULL_WITH_NULL_NULL} if the connection's crypto
	 * parameters have not yet been negotiated.
	 * 
	 * @return The current write state.
	 */
	DTLSConnectionState getWriteState() {
		return getWriteState(writeEpoch);
	}

	/**
	 * Get epoch specific write state.
	 * 
	 * @param epoch epoch of write state
	 * @return write state of provided epoch. {@code null}, if not available.
	 * @since 2.4
	 */
	DTLSConnectionState getWriteState(int epoch) {
		if (epoch == 0) {
			return DTLSConnectionState.NULL;
		} else {
			return writeState;
		}
	}

	/**
	 * Create the current write state of the connection.
	 * 
	 * The information in the current write state is used to en-crypt messages
	 * sent to a peer. See
	 * <a href="https://tools.ietf.org/html/rfc5246#section-6.1" target=
	 * "_blank"> RFC 5246 (TLS 1.2)</a> for details.
	 * 
	 * The <em>pending</em> write state becomes the <em>current</em> write state
	 * whenever a <em>CHANGE_CIPHER_SPEC</em> message is sent to a peer during a
	 * handshake.
	 * 
	 * This method also increments the write epoch and resets the session's
	 * sequence number counter to zero.
	 * 
	 * @param encryptionKey the secret key to use for encrypting message content
	 * @param iv the initialization vector to use for encrypting message content
	 * @param macKey the key to use for creating message authentication codes
	 *            (MAC)
	 * @throws NullPointerException if any of the parameter used by the provided
	 *             cipher suite is {@code null}
	 */
	public void createWriteState(SecretKey encryptionKey, SecretIvParameterSpec iv, SecretKey macKey) {
		DTLSConnectionState writeState = DTLSConnectionState.create(session.getCipherSuite(),
				session.getCompressionMethod(), encryptionKey, iv, macKey);
		SecretUtil.destroy(this.writeState);
		this.writeState = writeState;
		incrementWriteEpoch();
		LOGGER.trace("Setting current write state to{}{}", StringUtil.lineSeparator(), writeState);
	}

	/**
	 * Gets the name of the current write state's cipher suite.
	 * 
	 * @return the name.
	 */
	public String getWriteStateCipher() {
		return writeState.getCipherSuite().name();
	}

	/**
	 * The effective maximum message size for outgoing application data.
	 * 
	 * @param size effective maximum message size
	 */
	public void setEffectiveMaxMessageSize(int size) {
		effectiveMaxMessageSize = size;
	}

	/**
	 * Checks whether a given record can be processed within this DTLS context.
	 * 
	 * This is the case if
	 * <ul>
	 * <li>the record is from the same epoch as DTLS context's current read
	 * epoch</li>
	 * <li>the record has not been received before</li>
	 * <li>if marked as closed, the record's sequence number is not after the
	 * close notify's sequence number</li>
	 * </ul>
	 * 
	 * @param epoch the record's epoch
	 * @param sequenceNo the record's sequence number
	 * @param useExtendedWindow this value will be subtracted from to lower
	 *            receive window boundary. A value of {@code -1} will set that
	 *            calculated value to {@code 0}. Messages between lower receive
	 *            window boundary and that calculated value will pass the
	 *            filter, for other messages the filter is applied.
	 * @return {@code true} if the record satisfies the conditions above
	 * @throws IllegalArgumentException if the epoch differs from the current
	 *             read epoch
	 * @since 2.4
	 */
	public boolean isRecordProcessable(int epoch, long sequenceNo, int useExtendedWindow) {
		int readEpoch = getReadEpoch();
		if (epoch != readEpoch) {
			throw new IllegalArgumentException("wrong epoch! " + epoch + " != " + readEpoch);
		}
		if (sequenceNo < receiveWindowLowerBoundary) {
			// record lies out of receive window's "left" edge discard
			if (useExtendedWindow < 0) {
				// within extended window => pass
				return true;
			} else {
				// within extended window? => pass
				return sequenceNo > receiveWindowLowerBoundary - useExtendedWindow;
			}
		} else if (markedAsclosed) {
			if (epoch > readEpochClosed) {
				// record after close
				return false;
			} else if (epoch == readEpochClosed && sequenceNo >= readSequenceNumberClosed) {
				// record after close
				return false;
			}
			// otherwise, check for duplicate
		}
		return !isDuplicate(sequenceNo);
	}

	/**
	 * Checks, whether a given record has already been received during the
	 * current epoch.
	 * 
	 * The check is done based on a <em>sliding window</em> as described in
	 * <a href="https://tools.ietf.org/html/rfc6347#section-4.1.2.6" target=
	 * "_blank"> section 4.1.2.6 of the DTLS 1.2 spec</a>.
	 * 
	 * @param sequenceNo the record's sequence number
	 * @return {@code true}, if the record has already been received
	 */
	boolean isDuplicate(long sequenceNo) {
		if (sequenceNo > receiveWindowUpperCurrent) {
			return false;
		} else {

			// determine (zero based) index of record's sequence number within
			// receive window
			long idx = sequenceNo - receiveWindowLowerBoundary;
			// create bit mask for probing the bit representing position "idx"
			long bitMask = 1L << idx;
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug(
						"Checking sequence no [{}] using bit mask [{}] against received records [{}] with lower boundary [{}]",
						sequenceNo, Long.toBinaryString(bitMask), Long.toBinaryString(receivedRecordsVector),
						receiveWindowLowerBoundary);
			}
			return (receivedRecordsVector & bitMask) == bitMask;
		}
	}

	/**
	 * Marks a record as having been received so that it can be detected as a
	 * duplicate if it is received again, e.g. if a client re-transmits the
	 * record because it runs into a timeout.
	 * 
	 * The record is marked as received only, if it belongs to this DTLS
	 * context's current read epoch as indicated by {@link #getReadEpoch()}.
	 * 
	 * @param epoch the record's epoch
	 * @param sequenceNo the record's sequence number
	 * @return {@code true}, if the epoch/sequenceNo is newer than the current
	 *         newest. {@code false}, if not.
	 * @throws IllegalArgumentException if the epoch differs from the current
	 *             read epoch
	 */
	public boolean markRecordAsRead(int epoch, long sequenceNo) {
		int readEpoch = getReadEpoch();
		if (epoch != readEpoch) {
			throw new IllegalArgumentException("wrong epoch! " + epoch + " != " + readEpoch);
		}
		boolean newest = sequenceNo > receiveWindowUpperCurrent;
		if (newest) {
			receiveWindowUpperCurrent = sequenceNo;
			long lowerBoundary = Math.max(0, sequenceNo - RECEIVE_WINDOW_SIZE + 1);
			long incr = lowerBoundary - receiveWindowLowerBoundary;
			if (incr > 0) {
				// slide receive window to the right
				receivedRecordsVector = receivedRecordsVector >>> incr;
				receiveWindowLowerBoundary = lowerBoundary;
			}
		}
		long bitMask = 1L << (sequenceNo - receiveWindowLowerBoundary);
		// mark sequence number as "received" in receive window
		receivedRecordsVector |= bitMask;
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Updated receive window with sequence number [{}]: new upper boundary [{}], new bit vector [{}]",
					sequenceNo, receiveWindowUpperCurrent, Long.toBinaryString(receivedRecordsVector));
		}
		return newest;
	}

	/**
	 * DTLS context is marked as close.
	 * 
	 * @return {@code true}, if marked as closed, {@code false}, otherwise.
	 */
	public boolean isMarkedAsClosed() {
		return markedAsclosed;
	}

	/**
	 * Mark as closed. If a DTLS context is marked as closed, no records should
	 * be sent and no received newer records should be processed.
	 * 
	 * @param epoch epoch of close notify
	 * @param sequenceNo sequence number of close notify
	 * @see #isMarkedAsClosed()
	 */
	public void markCloseNotify(int epoch, long sequenceNo) {
		markedAsclosed = true;
		readEpochClosed = epoch;
		readSequenceNumberClosed = sequenceNo;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (int) (handshakeTime ^ (handshakeTime >>> 32));
		if (markedAsclosed) {
			result = prime * result + readEpochClosed;
			result = prime * result + (int) (readSequenceNumberClosed);
		} else {
			result = prime * result + readEpoch;
			result = prime * result + (int) (receiveWindowUpperCurrent);
		}
		result = prime * result + writeEpoch;
		result = prime * result + (int) sequenceNumbers[writeEpoch];
		result = prime * result + (int) (receiveWindowLowerBoundary);
		result = prime * result + (int) (receivedRecordsVector ^ (receivedRecordsVector >>> 32));
		result = prime * result + ((readConnectionId == null) ? 0 : readConnectionId.hashCode());
		result = prime * result + ((writeConnectionId == null) ? 0 : writeConnectionId.hashCode());
		result = prime * result + ((useDeprecatedCid) ? 1 : 0);
		result = prime * result + effectiveMaxMessageSize;
		result = prime * result + session.hashCode();
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		} else if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		DTLSContext other = (DTLSContext) obj;
		if (!session.equals(other.session)) {
			return false;
		}
		if (handshakeTime != other.handshakeTime) {
			return false;
		}
		if (markedAsclosed != other.markedAsclosed) {
			return false;
		}
		if (markedAsclosed) {
			if (readEpochClosed != other.readEpochClosed) {
				return false;
			}
			if (readSequenceNumberClosed != other.readSequenceNumberClosed) {
				return false;
			}
		}
		if (!Bytes.equals(readConnectionId, other.readConnectionId)) {
			return false;
		}
		if (!Bytes.equals(writeConnectionId, other.writeConnectionId)) {
			return false;
		}
		if (readEpoch != other.readEpoch) {
			return false;
		}
		if (receiveWindowLowerBoundary != other.receiveWindowLowerBoundary) {
			return false;
		}
		if (receiveWindowUpperCurrent != other.receiveWindowUpperCurrent) {
			return false;
		}
		if (receivedRecordsVector != other.receivedRecordsVector) {
			return false;
		}
		if (writeEpoch != other.writeEpoch) {
			return false;
		}
		if (sequenceNumbers[writeEpoch] != other.sequenceNumbers[writeEpoch]) {
			return false;
		}
		if (useDeprecatedCid != other.useDeprecatedCid) {
			return false;
		}
		if (effectiveMaxMessageSize != other.effectiveMaxMessageSize) {
			return false;
		}
		return true;
	}

	/**
	 * Re-initializes the receive window to detect duplicates for a new epoch.
	 * 
	 * The receive window is reset to sequence number zero and all information
	 * about received records is cleared.
	 */
	private void resetReceiveWindow() {
		receivedRecordsVector = 0;
		receiveWindowUpperCurrent = -1;
		receiveWindowLowerBoundary = 0;
	}

	/**
	 * Increment the number of MAC errors (including general encryption errors).
	 * 
	 * @since 3.0
	 */
	public void incrementMacErrors() {
		++macErrors;
	}

	/**
	 * Gets current number of MAC errors (including general encryption errors).
	 * 
	 * @return number of MAC errors
	 * @since 3.0
	 */
	public long getMacErrors() {
		return macErrors;
	}

	/**
	 * Version number for serialization.
	 */
	private static final int VERSION = 4;

	/**
	 * Version number for serialization before introducing
	 * {@link #useDeprecatedCid}.
	 */
	private static final int VERSION_DEPRECATED = 2;
	/**
	 * Version number for serialization before introducing
	 * {@link #useDeprecatedCid}.
	 */
	private static final int VERSION_DEPRECATED_2 = 3;

	private static final SupportedVersions VERSIONS = new SupportedVersions(VERSION, VERSION_DEPRECATED, VERSION_DEPRECATED_2);

	/**
	 * Write DTLS context state.
	 * 
	 * Only writes state, if not already marked as closed.
	 * 
	 * Note: the stream will contain not encrypted critical credentials. It is
	 * required to protect this data before exporting it.
	 * 
	 * @param writer writer for DTLS context state
	 * @return {@code true}, if connection was written, {@code false},
	 *         otherwise, if the dtls context is marked as closed.
	 */
	public boolean writeTo(DatagramWriter writer) {
		if (markedAsclosed) {
			return false;
		}
		int position = SerializationUtil.writeStartItem(writer, VERSION, Short.SIZE);
		writer.writeLong(handshakeTime, Long.SIZE);
		session.writeTo(writer);
		writer.write(readEpoch, Byte.SIZE);
		if (readEpoch > 0) {
			getReadState().writeTo(writer);
		}
		writer.write(writeEpoch, Byte.SIZE);
		if (writeEpoch > 0) {
			getWriteState().writeTo(writer);
		}
		writer.writeVarBytes(writeConnectionId, Byte.SIZE);
		writeSequenceNumbers(writer);
		// after deprecation
		writer.writeByte(useDeprecatedCid ? (byte) 1 : (byte) 0);
		writer.write(effectiveMaxMessageSize, Short.SIZE);
		// after deprecation_2
		writer.writeByte(supportExport ? (byte) 1 : (byte) 0);
		if (supportExport) {
			writer.writeVarBytes(clientRandom, Byte.SIZE);
			writer.writeVarBytes(serverRandom, Byte.SIZE);
		}
		SerializationUtil.writeFinishedItem(writer, position, Short.SIZE);
		return true;
	}

	/**
	 * Read DTLS context state.
	 * 
	 * @param reader reader with DTLS context state.
	 * @return read DTLS context.
	 * @throws IllegalArgumentException if version differs or the data is
	 *             erroneous
	 */
	public static DTLSContext fromReader(DatagramReader reader) {
		SupportedVersionsMatcher matcher = VERSIONS.matcher();
		int length = SerializationUtil.readStartItem(reader, matcher, Short.SIZE);
		if (0 < length) {
			DatagramReader rangeReader = reader.createRangeReader(length);
			return new DTLSContext(matcher.getReadVersion(), rangeReader);
		} else {
			return null;
		}
	}

	/**
	 * Create instance from reader.
	 * 
	 * @param version version of serialized data.
	 * @param reader reader with DTLS context state.
	 * @throws IllegalArgumentException if the data is erroneous
	 */
	private DTLSContext(int version, DatagramReader reader) {
		handshakeTime = reader.readLong(Long.SIZE);
		session = DTLSSession.fromReader(reader);
		if (session == null) {
			throw new IllegalArgumentException("read session must not be null!");
		}
		readEpoch = reader.read(Byte.SIZE);
		if (readEpoch > 0) {
			readState = DTLSConnectionState.fromReader(session.getCipherSuite(), session.getCompressionMethod(),
					reader);
		}
		writeEpoch = reader.read(Byte.SIZE);
		if (writeEpoch == 1) {
			writeState = DTLSConnectionState.fromReader(session.getCipherSuite(), session.getCompressionMethod(),
					reader);
		} else if (writeEpoch > 1) {
			throw new IllegalArgumentException("write epoch must be 1!");
		}
		byte[] data = reader.readVarBytes(Byte.SIZE);
		if (data != null) {
			writeConnectionId = new ConnectionId(data);
		}
		readSequenceNumbers(reader);
		if (version == VERSION_DEPRECATED) {
			useDeprecatedCid = true;
			effectiveMaxMessageSize = 0;
			supportExport = false;
		} else if (version == VERSION_DEPRECATED_2) {
			useDeprecatedCid = reader.readNextByte() == 1;
			effectiveMaxMessageSize = reader.read(Short.SIZE);
			supportExport = false;
		} else if (version == VERSION) {
			useDeprecatedCid = reader.readNextByte() == 1;
			effectiveMaxMessageSize = reader.read(Short.SIZE);
			supportExport = reader.readNextByte() == 1;
			if (supportExport) {
				data = reader.readVarBytes(Byte.SIZE);
				if (data != null) {
					clientRandom = new Random( data);
				}
				data = reader.readVarBytes(Byte.SIZE);
				if (data != null) {
					serverRandom = new Random( data);
				}
			}
		} else {
			supportExport = false;
		}
		reader.assertFinished("dtls-context");
	}

	/**
	 * Version number for sequence-number serialization.
	 */
	private static final int SEQN_VERSION = 1;

	/**
	 * Write the sequence-number state of this DTLS context.
	 * 
	 * @param writer writer for DTLS context state
	 */
	public void writeSequenceNumbers(DatagramWriter writer) {
		int position = SerializationUtil.writeStartItem(writer, SEQN_VERSION, Byte.SIZE);
		writer.writeLong(sequenceNumbers[writeEpoch], 48);
		writer.writeLong(receiveWindowLowerBoundary, 48);
		writer.writeLong(receivedRecordsVector, 64);
		writer.writeLong(macErrors, 64);
		SerializationUtil.writeFinishedItem(writer, position, Byte.SIZE);
	}

	/**
	 * Read the sequence-number state for this DTLS context.
	 * 
	 * @param reader reader with sequence-number state for DTLS context state
	 * @throws IllegalArgumentException if the data is erroneous
	 */
	public void readSequenceNumbers(DatagramReader reader) {
		int length = SerializationUtil.readStartItem(reader, SEQN_VERSION, Byte.SIZE);
		if (0 < length) {
			DatagramReader rangeReader = reader.createRangeReader(length);
			long sequenceNumber = rangeReader.readLong(48);
			long receiveLowerBoundary = rangeReader.readLong(48);
			long receivedVector = rangeReader.readLong(64);
			long errors = rangeReader.readLong(64);
			rangeReader.assertFinished("dtls-context-sequence-numbers");

			int zeros = Long.numberOfLeadingZeros(receivedVector);
			sequenceNumbers[writeEpoch] = sequenceNumber;
			receiveWindowLowerBoundary = receiveLowerBoundary;
			receivedRecordsVector = receivedVector;
			receiveWindowUpperCurrent = receiveLowerBoundary + Long.SIZE - zeros - 1;
			macErrors = errors;
		}
	}
}
