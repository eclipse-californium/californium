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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
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
	
	/**
	 * The remote peer of this session.
	 */
	private InetSocketAddress peer = null;
	
	/**
	 * An arbitrary byte sequence chosen by the server to identify an active or
	 * resumable session state.
	 */
	private SessionId sessionIdentifier = null;

	/** X509v3 certificate of the peer. This element of the state may be null. */
	private X509Certificate peerCertificate = null;

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
	 * A flag indicating whether the session can be used to initiate new
	 * connections.
	 */
	private boolean isResumable = false;

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
	private Map<Integer, Integer> sequenceNumbers = new HashMap<Integer, Integer>();
	
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

	private long receiveWindowUpperBoundary = RECEIVE_WINDOW_SIZE - 1;
	private long receivedRecordsVector = 0;
	
	
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
		this.peer = peerAddress;
		this.isClient = isClient;
		this.cipherSuite = CipherSuite.SSL_NULL_WITH_NULL_NULL;
		this.compressionMethod = CompressionMethod.NULL;
		this.sequenceNumbers.put(0, 0);
	}

	// Getters and Setters ////////////////////////////////////////////

	public SessionId getSessionIdentifier() {
		return sessionIdentifier;
	}

	public void setSessionIdentifier(SessionId sessionIdentifier) {
		this.sessionIdentifier = sessionIdentifier;
	}

	public X509Certificate getPeerCertificate() {
		return peerCertificate;
	}

	public void setPeerCertificate(X509Certificate peerCertificate) {
		this.peerCertificate = peerCertificate;
	}

	public PublicKey getPeerRawPublicKey() {
		return peerRawPublicKey;
	}

	public void setPeerRawPublicKey(PublicKey key) {
		peerRawPublicKey = key;
	}

	public CompressionMethod getCompressionMethod() {
		return compressionMethod;
	}

	public void setCompressionMethod(CompressionMethod compressionMethod) {
		this.compressionMethod = compressionMethod;
	}

	public CipherSuite getCipherSuite() {
		return cipherSuite;
	}

	public void setCipherSuite(CipherSuite cipherSuite) {
		this.cipherSuite = cipherSuite;
	}

	public boolean isResumable() {
		return isResumable;
	}

	public void setResumable(boolean isResumable) {
		this.isResumable = isResumable;
	}

	public boolean isActive() {
		return active;
	}

	public void setActive(boolean isActive) {
		this.active = isActive;
	}

	public boolean isClient() {
		return this.isClient;
	}

	public void setClient(boolean isClient) {
		this.isClient = isClient;
	}

	public int getWriteEpoch() {
		return writeEpoch;
	}
	
	public void setWriteEpoch(int epoch) {
		this.writeEpoch = epoch;
	}

	public int getReadEpoch() {
		return readEpoch;
	}
	
	public void setReadEpoch(int epoch) {
		resetReceiveWindow();
		this.readEpoch = epoch;
	}

	public void incrementReadEpoch() {
		resetReceiveWindow();
		this.readEpoch++;
	}

	/**
	 * Increments the epoch and sets the sequence number of the new epoch to 0.
	 */
	public void incrementWriteEpoch() {
		this.writeEpoch++;
		// Sequence numbers are maintained separately for each epoch, with each
		// sequence_number initially being 0 for each epoch.
		this.sequenceNumbers.put(writeEpoch, 0);
	}

	public int getSequenceNumber() {
		return getSequenceNumber(writeEpoch);
	}

	/**
	 * Gets the smallest unused sequence number from this epoch.
	 * 
	 * @param epoch
	 *            the epoch from which to get the sequence number.
	 * @return the next sequence number.
	 */
	public int getSequenceNumber(int epoch) {
		int sequenceNumber = this.sequenceNumbers.get(epoch);
		this.sequenceNumbers.put(epoch, sequenceNumber + 1);
		return sequenceNumber;
	}

	public DTLSConnectionState getReadState() {
		return readState;
	}

	public void setReadState(DTLSConnectionState readState) {
		this.readState = readState;
	}

	public DTLSConnectionState getWriteState() {
		return writeState;
	}

	public void setWriteState(DTLSConnectionState writeState) {
		this.writeState = writeState;
	}

	public KeyExchangeAlgorithm getKeyExchange() {
		return keyExchange;
	}

	public void setKeyExchange(KeyExchangeAlgorithm keyExchange) {
		this.keyExchange = keyExchange;
	}

	public byte[] getMasterSecret() {
		return masterSecret;
	}

	public void setMasterSecret(byte[] masterSecret) {
		// don't overwrite the master secret, once it has been set in this session
		if (this.masterSecret != null) {
			this.masterSecret = masterSecret;
		}
	}

	public boolean sendRawPublicKey() {
		return sendRawPublicKey;
	}

	public void setSendRawPublicKey(boolean sendRawPublicKey) {
		this.sendRawPublicKey = sendRawPublicKey;
	}

	public boolean receiveRawPublicKey() {
		return receiveRawPublicKey;
	}

	public void setReceiveRawPublicKey(boolean receiveRawPublicKey) {
		this.receiveRawPublicKey = receiveRawPublicKey;
	}

	public InetSocketAddress getPeer() {
		return peer;
	}
	
	public String getPskIdentity() {
        return pskIdentity;
    }

    public void setPskIdentity(String pskIdentity) {
        this.pskIdentity = pskIdentity;
    }

    /**
     * Checks whether a given record can be processed within the context
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
				if (sequenceNo < getLowerBoundary()) {
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
	private synchronized boolean isDuplicate(long sequenceNo) {
		if (sequenceNo > receiveWindowUpperBoundary) {
			return false;
		} else {
			
			// determine (zero based) index of record's sequence number within receive window
			long idx = sequenceNo - getLowerBoundary();
			// create bit mask for probing the bit representing position "idx" 
			long bitMask = 1L << idx;
			LOGGER.log(Level.FINE,
					"Checking sequence no [{0}] using bit mask [{1}] against received records [{2}] with lower boundary [{3}]",
					new Object[]{sequenceNo, Long.toBinaryString(bitMask), Long.toBinaryString(receivedRecordsVector), getLowerBoundary()});
			return (receivedRecordsVector & bitMask) == bitMask;
		}
	}
		
	private synchronized long getLowerBoundary() {
		return Math.max(0, receiveWindowUpperBoundary - RECEIVE_WINDOW_SIZE + 1);
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
			}
			long bitMask = 1L << (sequenceNo - getLowerBoundary());
			// mark sequence number as "received" in receive window
			receivedRecordsVector |= bitMask;
			LOGGER.log(Level.FINE, "Updated receive window with sequence number [{0}]: new upper boundary [{1}], new bit vector [{2}]",
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
	}
    
}