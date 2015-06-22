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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add duplicate record
 *                                                    detection functionality
 *                                                  - manage record sequence numbers
 *                                                    as Long values reducing the
 *                                                    need for type conversions
 *    Kai Hudalla (Bosch Software Innovations GmbH) - reduce method visibility to improve encapsulation,
 *                                                    synchronize methods to allow for concurrent access
 *    Kai Hudalla (Bosch Software Innovations GmbH) - provide access to peer's identity as a
 *                                                    java.security.Principal (fix 464812)
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.security.Principal;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;


/**
 * Represents a DTLS session between two peers. Keeps track of the current and
 * pending read/write states, the current epoch and sequence number, etc.
 */
public class DTLSSession {
	
	private static final Logger LOGGER = Logger.getLogger(DTLSSession.class.getName());
	private static final int RECEIVE_WINDOW_SIZE = 64;
	private static final long MAX_SEQUENCE_NO = 281474976710655L; // 2^48 - 1
	
	/**
	 * The remote peer of this session.
	 */
	private InetSocketAddress peer = null;
	
	/**
	 * An arbitrary byte sequence chosen by the server to identify an active or
	 * resumable session state.
	 */
	private SessionId sessionIdentifier = null;

	private Principal peerIdentity;
	
	/** The algorithm used to compress data prior to encryption. */
	private CompressionMethod compressionMethod;

	/**
	 * Specifies the pseudorandom function (PRF) used to generate keying
	 * material, the bulk data encryption algorithm (such as null, AES, etc.)
	 * and the MAC algorithm (such as HMAC-SHA1). It also defines cryptographic
	 * attributes such as the mac_length. (See Appendix A.6 for formal
	 * definition.)
	 */
	private CipherSuite cipherSuite;

	/** 48-byte secret shared between the client and server. */
	private byte[] masterSecret = null;

	/**
	 * The identity used for PSK authentication
	 */
	private String pskIdentity;

	/**
	 * The peer public key for RPK authentication
	 */
	private PublicKey peerRawPublicKey;	

	/**
	 * Whether the session is active and application data can be sent to the
	 * peer.
	 */
	private boolean active = false;

	/**
	 * Whether this entity is considered the "client" or the "server" in this
	 * connection.
	 */
	private boolean isClient;

	private DTLSConnectionState readState = new DTLSConnectionState();
	private DTLSConnectionState writeState = new DTLSConnectionState();

	/** The current epoch, incremented with every Change Cipher Spec. */
	private int readEpoch = 0;
	private int writeEpoch = 0;

	/** The next sequence number the record must have for each epoch separately. */
	private Map<Integer, Long> sequenceNumbers = new HashMap<>();
	
	/** The key exchange algorithm used in this session. */
	private KeyExchangeAlgorithm keyExchange;
	
	/**
	 * Indicates whether only the RawPublicKey is sent or a full X.509
	 * certificates.
	 */
	private boolean sendRawPublicKey = false;
	
	/**
	 * Indicates whether the peer sends a RawPublicKey.
	 */
	private boolean receiveRawPublicKey = false;

	private volatile long receiveWindowUpperBoundary = RECEIVE_WINDOW_SIZE - 1;
	private volatile long receiveWindowLowerBoundary = 0;
	private volatile long receivedRecordsVector = 0;
	
	
	// Constructor ////////////////////////////////////////////////////

	/**
	 * Called when initializing a fresh session.
	 *
	 * @param peerAddress
	 *            the remote address
	 * @param isClient
	 *            whether the entity represents a client or a server.
	 */
	public DTLSSession(InetSocketAddress peerAddress, boolean isClient) {
		this(peerAddress, isClient, 0);
	}
	
	
	/**
	 * Creates a new session initialized with a given sequence number.
	 *
	 * @param peerAddress
	 *            the IP address and port of the peer this session is established with
	 * @param isClient
	 *            indicates whether this session has been established playing the client or server side
	 * @param initialSequenceNo the initial record sequence number to start from
	 *            in epoch 0. When starting a new handshake with a client that
	 *            has successfully exchanged a cookie with the server, the
	 *            sequence number to use in the SERVER_HELLO record MUST be the same as
	 *            the one from the successfully validated CLIENT_HELLO record
	 *            (see <a href="http://tools.ietf.org/html/rfc6347#section-4.2.1">
	 *            section 4.2.1 of RFC 6347 (DTLS 1.2)</a> for details)
	 */
	public DTLSSession(InetSocketAddress peerAddress, boolean isClient, long initialSequenceNo) {
		if (peerAddress == null) {
			throw new NullPointerException("Peer address must not be null");
		} else if (initialSequenceNo < 0 || initialSequenceNo > MAX_SEQUENCE_NO) {
			throw new IllegalArgumentException("Initial sequence number must be greater than 0 and less than 2^48");
		} else {
			this.peer = peerAddress;
			this.isClient = isClient;
			this.cipherSuite = CipherSuite.TLS_NULL_WITH_NULL_NULL;
			this.compressionMethod = CompressionMethod.NULL;
			this.sequenceNumbers.put(0, initialSequenceNo);
			// initialize current read/write state with NULL cipher suite
			this.readState = new DTLSConnectionState();
			this.writeState = new DTLSConnectionState();
		}
	}

	// Getters and Setters ////////////////////////////////////////////

	public SessionId getSessionIdentifier() {
		return sessionIdentifier;
	}

	final synchronized void setSessionIdentifier(SessionId sessionIdentifier) {
		this.sessionIdentifier = sessionIdentifier;
	}

	/**
	 * Gets the public key presented by a peer during an ECDH based
	 * handshake.
	 * 
	 * @return the public key or <code>null</code> if the peer has not
	 * been authenticated or the handshake was PSK based
	 * @deprecated Use {@link #getPeerIdentity()} instead
	 */
	public final PublicKey getPeerRawPublicKey() {
		return peerRawPublicKey;
	}

	/**
	 * 
	 * @param key
	 * @deprecated Use {@link #setPeerIdentity(Principal)} instead
	 */
	final synchronized void setPeerRawPublicKey(PublicKey key) {
		peerRawPublicKey = key;
	}

	public CompressionMethod getCompressionMethod() {
		return compressionMethod;
	}

	public void setCompressionMethod(CompressionMethod compressionMethod) {
		this.compressionMethod = compressionMethod;
	}

	final CipherSuite getCipherSuite() {
		return cipherSuite;
	}

	/**
	 * Sets the cipher suite to be used for this session.
	 *  
	 * @param cipherSuite the cipher suite
	 */
	final synchronized void setCipherSuite(CipherSuite cipherSuite) {
		this.cipherSuite = cipherSuite;
		this.keyExchange = cipherSuite.getKeyExchange();
	}

	public synchronized final boolean isActive() {
		return active;
	}

	public final synchronized void setActive(boolean isActive) {
		this.active = isActive;
	}

	public final boolean isClient() {
		return this.isClient;
	}

	public final int getWriteEpoch() {
		return writeEpoch;
	}
	
	final synchronized void setWriteEpoch(int epoch) {
		if (epoch < 0) {
			throw new IllegalArgumentException("Write epoch must not be negative");
		} else {
			this.writeEpoch = epoch;
		}
	}

	public final int getReadEpoch() {
		return readEpoch;
	}
	
	final synchronized void setReadEpoch(int epoch) {
		if (epoch < 0) {
			throw new IllegalArgumentException("Read epoch must not be negative");
		} else {
			resetReceiveWindow();
			this.readEpoch = epoch;
		}
	}

	private synchronized void incrementReadEpoch() {
		resetReceiveWindow();
		this.readEpoch++;
	}

	/**
	 * Increments the epoch and sets the sequence number of the new epoch to 0.
	 */
	private synchronized void incrementWriteEpoch() {
		this.writeEpoch++;
		// Sequence numbers are maintained separately for each epoch, with each
		// sequence_number initially being 0 for each epoch.
		this.sequenceNumbers.put(writeEpoch, 0L);
	}

	/**
	 * Gets the smallest unused sequence number for outbound records
	 * for the current epoch.
	 * 
	 * @return the next sequence number
	 * @throws IllegalStateException if the maximum sequence number for the
	 *     epoch has been reached (2^48 - 1)
	 */
	public final synchronized long getSequenceNumber() {
		return getSequenceNumber(writeEpoch);
	}

	/**
	 * Gets the smallest unused sequence number for outbound records
	 * for a given epoch.
	 * 
	 * @param epoch
	 *            the epoch for which to get the sequence number
	 * @return the next sequence number
	 * @throws IllegalStateException if the maximum sequence number for the
	 *     epoch has been reached (2^48 - 1)
	 */
	public final synchronized long getSequenceNumber(int epoch) {
		long sequenceNumber = this.sequenceNumbers.get(epoch);
		if (sequenceNumber < MAX_SEQUENCE_NO) {
			this.sequenceNumbers.put(epoch, sequenceNumber + 1);
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
	 * 
	 * The information in the current read state is used to de-crypt
	 * messages received from a peer.
	 * See <a href="http://tools.ietf.org/html/rfc5246#section-6.1">
	 * RFC 5246 (TLS 1.2)</a> for details.
	 * 
	 * @return the current read state
	 */
	final DTLSConnectionState getReadState() {
		return readState;
	}

	/**
	 * Sets the current read state of the connection.
	 * 
	 * The information in the current read state is used to de-crypt
	 * messages received from a peer.
	 * See <a href="http://tools.ietf.org/html/rfc5246#section-6.1">
	 * RFC 5246 (TLS 1.2)</a> for details.
	 * 
	 * The <em>pending</em> read state becomes the <em>current</em>
	 * read state whenever a <em>CHANGE_CIPHER_SPEC</em> message is
	 * received from a peer during a handshake.
	 * 
	 * This method also increments the read epoch.
	 * 
	 * @param readState the current read state
	 * @throws NullPointerException if the given state is <code>null</code>
	 */
	final synchronized void setReadState(DTLSConnectionState readState) {
		if (readState == null) {
			throw new NullPointerException("Read state must not be null");
		}
		this.readState = readState;
		incrementReadEpoch();
		LOGGER.log(Level.FINEST, "Setting current read state to\n{0}", readState);
	}

	/**
	 * Gets the current write state of the connection.
	 * 
	 * The information in the current write state is used to en-crypt
	 * messages sent to a peer.
	 * See <a href="http://tools.ietf.org/html/rfc5246#section-6.1">
	 * RFC 5246 (TLS 1.2)</a> for details.
	 * 
	 * @return the current read state
	 */
	final DTLSConnectionState getWriteState() {
		return writeState;
	}

	/**
	 * Sets the current write state of the connection.
	 * 
	 * The information in the current write state is used to en-crypt
	 * messages sent to a peer.
	 * See <a href="http://tools.ietf.org/html/rfc5246#section-6.1">
	 * RFC 5246 (TLS 1.2)</a> for details.
	 * 
	 * The <em>pending</em> write state becomes the <em>current</em>
	 * write state whenever a <em>CHANGE_CIPHER_SPEC</em> message is
	 * received from a peer during a handshake.
	 * 
	 * This method also increments the write epoch and resets the session's
	 * sequence number counter to zero.
	 * 
	 * @param writeState the current write state
	 * @throws NullPointerException if the given state is <code>null</code>
	 */
	final synchronized void setWriteState(DTLSConnectionState writeState) {
		if (writeState == null) {
			throw new NullPointerException("Write state must not be null");
		}
		this.writeState = writeState;
		incrementWriteEpoch();
		LOGGER.log(Level.FINEST, "Setting current write state to\n{0}", writeState);
	}

	final KeyExchangeAlgorithm getKeyExchange() {
		return keyExchange;
	}

	/**
	 * Gets the master secret used for encrypting application layer data
	 * exchanged in this session.
	 * 
	 * @return the secret or <code>null</code> if it has not yet been
	 * created
	 */
	final byte[] getMasterSecret() {
		return masterSecret;
	}

	/**
	 * Sets the master secret to use for encrypting application layer data
	 * exchanged in this session.
	 * 
	 * Once the master secret has been set, it cannot be changed.
	 * 
	 * @param masterSecret the secret
	 * @throws NullPointerException if the secret is <code>null</code>
	 * @throws IllegalArgumentException if the secret is not exactly 48 bytes
	 * (see <a href="http://tools.ietf.org/html/rfc5246#section-8.1">
	 * RFC 5246 (TLS 1.2), section 8.1</a>) 
	 */
	void setMasterSecret(byte[] masterSecret) {
		// don't overwrite the master secret, once it has been set in this session
		if (this.masterSecret == null) {
			if (masterSecret == null) {
				throw new NullPointerException("Master secret must not be null");
			} else if (masterSecret.length != 48) {
				throw new IllegalArgumentException(String.format(
						"Master secret must consist of of exactly 48 bytes but has [%d] bytes",
						masterSecret.length));
			} else {
				this.masterSecret = masterSecret;
			}
		}
	}

	final boolean sendRawPublicKey() {
		return sendRawPublicKey;
	}

	final synchronized void setSendRawPublicKey(boolean sendRawPublicKey) {
		this.sendRawPublicKey = sendRawPublicKey;
	}

	final boolean receiveRawPublicKey() {
		return receiveRawPublicKey;
	}

	final synchronized void setReceiveRawPublicKey(boolean receiveRawPublicKey) {
		this.receiveRawPublicKey = receiveRawPublicKey;
	}

	public InetSocketAddress getPeer() {
		return peer;
	}
	
	/**
	 * Gets the authenticated peer's identity.
	 * 
	 * @return the identity or <code>null</code> if the peer has not been
	 * authenticated
	 */
	public final Principal getPeerIdentity() {
		return peerIdentity;
	}
	
	/**
	 * Sets the authenticated peer's identity.
	 * 
	 * @param the identity
	 * @throws NullPointerException if the identity is <code>null</code>
	 */
	final synchronized void setPeerIdentity(Principal peerIdentity) {
		if (peerIdentity == null) {
			throw new NullPointerException("Peer identity must not be null");
		}
		this.peerIdentity = peerIdentity;
	}
	
	/**
	 * Gets the identity presented by a peer during a <em>pre-shared key</em>
	 * based handshake.
	 * 
	 * @return the (authenticated) identity or <code>null</code> if the peer
	 * has not been authenticated at all or the handshake was ECDH based
	 * @deprecated Use {@link #getPeerIdentity()} instead
	 */
	public final String getPskIdentity() {
		return pskIdentity;
	}

	/**
	 * 
	 * @param pskIdentity
	 * @deprecated Use {@link #setPeerIdentity(Principal)} instead
	 */
	final synchronized void setPskIdentity(String pskIdentity) {
		this.pskIdentity = pskIdentity;
	}

	/**
	 * * Checks whether a given record can be processed within the context
	 * of this session.
	 * 
	 * This is the case if
	 * <ul>
	 * <li>the record is from the same epoch as session's current read epoch</li>
	 * <li>the record has not been received before</li>
	 * </ul>
	 *  
	 * @param epoch the record's epoch
	 * @param sequenceNo the record's sequence number
	 * @return <code>true</code> if the record satisfies the conditions above
	 */
    public final boolean isRecordProcessable(long epoch, long sequenceNo) {
		if (epoch < getReadEpoch()) {
			// record is from a previous epoch
			// discard record as proposed in DTLS 1.2
			// http://tools.ietf.org/html/rfc6347#section-4.1
			return false;
		} else if (epoch > getReadEpoch()) {
			// record is from future epoch
			// discard record as allowed in DTLS 1.2
			// http://tools.ietf.org/html/rfc6347#section-4.1
			return false;
		} else {
			synchronized (this) {
				if (sequenceNo < receiveWindowLowerBoundary) {
					// record lies out of receive window's "left" edge
					// discard
					return false;
				} else {
					return !isDuplicate(sequenceNo);
				}
			}
		}
	}

	/**
	 * Checks whether a given record has already been received during the
	 * current epoch.
	 * 
	 * The check is done based on a <em>sliding window</em> as described in
	 * <a href="http://tools.ietf.org/html/rfc6347#section-4.1.2.6">
	 * section 4.1.2.6 of the DTLS 1.2 spec</a>.
	 * 
	 * @param sequenceNo the record's sequence number
	 * @return <code>true</code> if the record has already been received
	 */
	synchronized boolean isDuplicate(long sequenceNo) {
		if (sequenceNo > receiveWindowUpperBoundary) {
			return false;
		} else {
			
			// determine (zero based) index of record's sequence number within receive window
			long idx = sequenceNo - receiveWindowLowerBoundary;
			// create bit mask for probing the bit representing position "idx" 
			long bitMask = 1L << idx;
			if (LOGGER.isLoggable(Level.FINER)) {
				LOGGER.log(Level.FINER,
						"Checking sequence no [{0}] using bit mask [{1}] against received records [{2}] with lower boundary [{3}]",
						new Object[]{sequenceNo, Long.toBinaryString(bitMask), Long.toBinaryString(receivedRecordsVector),
						receiveWindowLowerBoundary});
			}
			return (receivedRecordsVector & bitMask) == bitMask;
		}
	}

	/**
	 * Marks a record as having been received so that it can be detected
	 * as a duplicate if it is received again, e.g. if a client re-transmits
	 * the record because it runs into a timeout.
	 * 
	 * The record is marked as received only if it belongs to this session's
	 * current read epoch as indicated by {@link #getReadEpoch()}.
	 * 
	 * @param epoch the record's epoch
	 * @param sequenceNo the record's sequence number
	 */
	public final synchronized void markRecordAsRead(long epoch, long sequenceNo) {

		if (epoch == getReadEpoch()) {
			if (sequenceNo > receiveWindowUpperBoundary) {
				long incr = sequenceNo - receiveWindowUpperBoundary;
				receiveWindowUpperBoundary = sequenceNo;
				// slide receive window to the right
				receivedRecordsVector = receivedRecordsVector >>> incr;
				receiveWindowLowerBoundary = Math.max(0, receiveWindowUpperBoundary - RECEIVE_WINDOW_SIZE + 1);
			}
			long bitMask = 1L << (sequenceNo - receiveWindowLowerBoundary);
			// mark sequence number as "received" in receive window
			receivedRecordsVector |= bitMask;
			LOGGER.log(Level.FINER, "Updated receive window with sequence number [{0}]: new upper boundary [{1}], new bit vector [{2}]",
					new Object[]{sequenceNo, receiveWindowUpperBoundary, Long.toBinaryString(receivedRecordsVector)});
		}
	}
	
	/**
	 * Re-initializes the receive window to detect duplicates for a new epoch.
	 * 
	 * The receive window is reset to sequence number zero and all
	 * information about received records is cleared.
	 */
	private synchronized void resetReceiveWindow() {
		receivedRecordsVector = 0;
		receiveWindowUpperBoundary = RECEIVE_WINDOW_SIZE - 1;
		receiveWindowLowerBoundary = 0;
	}
}
