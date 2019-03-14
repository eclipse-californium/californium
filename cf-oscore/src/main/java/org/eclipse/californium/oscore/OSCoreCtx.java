/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
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
 *    Joakim Brorsson
 *    Ludwig Seitz (RISE SICS)
 *    Tobias Andersson (RISE SICS)
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.core.coap.CoAP.Code;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;

/**
 * 
 * Represents the Security Context and its parameters. At initiation derives the
 * keys and IVs. Also maintains replay window.
 *
 */
public class OSCoreCtx {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(OSCoreCtx.class.getName());

	private AlgorithmID common_alg;
	private byte[] common_master_secret;
	private byte[] common_master_salt;
	private byte[] common_iv;
	private byte[] context_id;

	private byte[] sender_id;
	private byte[] sender_key;
	private int sender_seq;

	private byte[] recipient_id;
	private byte[] recipient_key;
	private int recipient_seq;
	private int recipient_replay_window_size;
	private int recipient_replay_window;

	private AlgorithmID kdf;

	private int rollback_recipient_seq = -1;
	private int rollback_recipient_replay = -1;
	private byte[] rollback_last_block_tag = null;

	private byte[] last_block_tag = null;
	private int seqMax = Integer.MAX_VALUE;

	private int id_length;
	private int iv_length;
	private int key_length;

	private Code CoAPCode = null;

	/**
	 * Constructor. Generates the context from the base parameters with the
	 * minimal input.
	 * 
	 * @param master_secret the master secret
	 * @param client is this originally the client's context
	 * @throws OSException if the default KDF is not supported
	 */
	public OSCoreCtx(byte[] master_secret, boolean client) throws OSException {
		this(master_secret, client, null, null, null, null, null, null, null);
	}

	/**
	 * Constructor. Generates the context from the base parameters.
	 * 
	 * @param master_secret the master secret
	 * @param alg the encryption algorithm as defined in COSE
	 * @param client is this originally the client's context
	 * @param sender_id the sender id or null for default
	 * @param recipient_id the recipient id or null for default
	 * @param kdf the COSE algorithm abbreviation of the kdf or null for the
	 *            default
	 * @param replay_size the replay window size or null for the default
	 * @param master_salt the optional master salt, can be null
	 * @param contextId the context id, can be null
	 *
	 * @throws OSException if the KDF is not supported
	 */
	public OSCoreCtx(byte[] master_secret, boolean client, AlgorithmID alg, byte[] sender_id, byte[] recipient_id,
			AlgorithmID kdf, Integer replay_size, byte[] master_salt, byte[] contextId) throws OSException {

		if (alg == null) {
			this.common_alg = AlgorithmID.AES_CCM_16_64_128;
		} else {
			this.common_alg = alg;
		}

		setLengths();

		this.sender_seq = 0;
		this.recipient_seq = -1;

		if (master_secret != null) {
			this.common_master_secret = master_secret.clone();
		} else {
			LOGGER.error("Input master secret is null");
			throw new NullPointerException("Input master secret is null");
		}
		if (sender_id == null || sender_id.length > this.id_length) {
			if (client) {
				this.sender_id = new byte[] { 0x00 };
			} else {
				this.sender_id = new byte[] { 0x01 };
			}
		} else {
			this.sender_id = sender_id.clone();
		}

		if (recipient_id == null || recipient_id.length > this.id_length) {
			if (client) {
				this.recipient_id = new byte[] { 0x01 };
			} else {
				this.recipient_id = new byte[] { 0x00 };
			}
		} else {
			this.recipient_id = recipient_id.clone();
		}

		if (kdf == null) {
			this.kdf = AlgorithmID.HKDF_HMAC_SHA_256;
		} else {
			this.kdf = kdf;
		}

		if (replay_size == null) {
			this.recipient_replay_window_size = 32;
		} else {
			this.recipient_replay_window_size = replay_size.intValue();
		}
		this.recipient_replay_window = 0;

		if (master_salt == null) {
			// Default value. Automatically initialized with 0-es.
			this.common_master_salt = new byte[this.kdf.getKeySize() / 8];
		} else {
			this.common_master_salt = master_salt.clone();
		}

		if (contextId != null) {
			this.context_id = contextId.clone();
		} else {
			this.context_id = null;
		}

		String digest = null;
		switch (this.kdf) {
		case HKDF_HMAC_SHA_256:
			digest = "SHA256";
			break;
		case HKDF_HMAC_SHA_512:
			digest = "SHA512";
			break;
		case HKDF_HMAC_AES_128:
		case HKDF_HMAC_AES_256:
		default:
			LOGGER.error("Requested HKDF algorithm is not supported: " + this.kdf.toString());
			throw new OSException("HKDF algorithm not supported");
		}

		// Derive sender_key
		CBORObject info = CBORObject.NewArray();
		info.Add(this.sender_id);
		info.Add(this.context_id);
		info.Add(this.common_alg.AsCBOR());
		info.Add(CBORObject.FromObject("Key"));
		info.Add(this.key_length);

		try {
			this.sender_key = deriveKey(this.common_master_secret, this.common_master_salt, this.key_length, digest,
					info.EncodeToBytes());
		} catch (CoseException e) {
			LOGGER.error(e.getMessage());
			throw new OSException(e.getMessage());
		}

		// Derive recipient_key
		info = CBORObject.NewArray();
		info.Add(this.recipient_id);
		info.Add(this.context_id);
		info.Add(this.common_alg.AsCBOR());
		info.Add(CBORObject.FromObject("Key"));
		info.Add(this.key_length);

		try {
			this.recipient_key = deriveKey(this.common_master_secret, this.common_master_salt, this.key_length, digest,
					info.EncodeToBytes());
		} catch (CoseException e) {
			LOGGER.error(e.getMessage());
			throw new OSException(e.getMessage());
		}

		// Derive common_iv
		info = CBORObject.NewArray();
		info.Add(new byte[0]);
		info.Add(this.context_id);
		info.Add(this.common_alg.AsCBOR());
		info.Add(CBORObject.FromObject("IV"));
		info.Add(this.iv_length);

		try {
			this.common_iv = deriveKey(this.common_master_secret, this.common_master_salt, this.iv_length, digest,
					info.EncodeToBytes());
		} catch (CoseException e) {
			LOGGER.error(e.getMessage());
			throw new OSException(e.getMessage());
		}

	}

	/**
	 * Overrides hasCode to provide a functional implementation for this class.
	 */
	@Override
	public int hashCode() {
		byte[] c = new byte[sender_id.length + recipient_id.length];
		System.arraycopy(sender_id, 0, c, 0, sender_id.length);
		System.arraycopy(recipient_id, 0, c, sender_id.length, recipient_id.length);
		return ByteBuffer.wrap(c).hashCode();
	}

	/**
	 * Overrides equals to provide a functional implementation for this class.
	 */
	@Override
	public boolean equals(Object o) {
		if (!(o instanceof OSCoreCtx)) {
			return false;
		}
		OSCoreCtx other = (OSCoreCtx) o;

		return Arrays.equals(other.sender_id, sender_id) && Arrays.equals(other.recipient_id, recipient_id);
	}

	/**
	 * @return the sender key
	 */
	public byte[] getSenderKey() {
		return sender_key;
	}

	/**
	 * @return the recipient key
	 */
	public byte[] getRecipientKey() {
		return recipient_key;
	}

	/**
	 * @return the encryption algorithm
	 */
	public AlgorithmID getAlg() {
		return this.common_alg;
	}

	/**
	 * @return the sender sequence number
	 */
	public synchronized int getSenderSeq() {
		return sender_seq;
	}

	/**
	 * @return the receiver sequence number
	 */
	public synchronized int getReceiverSeq() {
		return recipient_seq;
	}

	/**
	 * @return the tag of the last block processed with this context
	 */
	public byte[] getLastBlockTag() {
		return last_block_tag;
	}

	/**
	 * @return the sender's identifier
	 */
	public byte[] getSenderId() {
		return sender_id;
	}

	/**
	 * @return the repipient's identifier
	 */
	public byte[] getRecipientId() {
		return recipient_id;
	}

	/**
	 * @return the common_iv
	 */
	public byte[] getCommonIV() {
		return common_iv;
	}

	/**
	 * @return the set length of IV:s
	 */
	public int getIVLength() {
		return iv_length;
	}

	/**
	 * @return size of recipient replay window
	 */
	public int getRecipientReplaySize() {
		return recipient_replay_window_size;
	}

	/**
	 * @return recipient replay window
	 */
	public int getRecipientReplayWindow() {
		return recipient_replay_window;
	}

	public byte[] getMasterSecret() {
		return common_master_secret;
	}

	public byte[] getSalt() {
		return common_master_salt;
	}

	public AlgorithmID getKdf() {
		return kdf;
	}
	
	/**
	 * Enables getting the ID Context
	 * 
	 * @return Byte array with ID Context
	 */
	public byte[] getIdContext() {
		return context_id;
	}

	public int rollbackRecipientSeq() {
		return rollback_recipient_seq;
	}

	public int rollbackRecipientReplay() {
		return rollback_recipient_replay;
	}

	/**
	 * @param seq the sender sequence number to set
	 */
	public synchronized void setSenderSeq(int seq) {
		sender_seq = seq;
	}

	/**
	 * @param seq the recipient sequence number to set
	 */
	public synchronized void setReceiverSeq(int seq) {
		recipient_seq = seq;
	}

	/**
	 * Save the tag of the last processed block
	 * 
	 * @param tag the tag
	 */
	public void setLastBlockTag(byte[] tag) {
		last_block_tag = tag.clone();
	}

	/**
	 * Enables setting the sender key
	 * 
	 * @param senderKey
	 */
	public void setSenderKey(byte[] senderKey) {
		this.sender_key = senderKey.clone();
	}
	
	/**
	 * Enables setting the recipient key
	 * 
	 * @param recipientKey
	 */
	public void setRecipientKey(byte[] recipientKey) {
		this.recipient_key = recipientKey.clone();
	}
	
	/**
	 * Set the maximum sequence number.
	 * 
	 * @param seqMax the maximum sequence number.
	 */
	public void setSeqMax(int seqMax) {
		this.seqMax = seqMax;
	}

	/**
	 * Sets the valid lengths, in bytes, of constrained variables(ids, IVs and
	 * keys).
	 * 
	 * @throws RuntimeException if not this.common_alg has been initiated
	 */
	private void setLengths() {
		if (common_alg != null) {
			if (common_alg.equals(AlgorithmID.AES_CCM_16_64_128)) {
				iv_length = ivLength(common_alg);
				id_length = 7;
				key_length = common_alg.getKeySize() / 8; // 16;
			} else {
				LOGGER.error("Unable to set lengths, since algorithm");
				throw new RuntimeException("Unable to set lengths, since algorithm");
			}
		} else {
			LOGGER.error("Common_alg has not yet been initiated.");
			throw new RuntimeException("Common_alg has not yet been initiated.");
		}
	}

	/**
	 * Increase the sender's sequence number by one
	 *
	 * @throws OSException if the sequence number wraps
	 */
	public synchronized void increaseSenderSeq() throws OSException {
		if (sender_seq >= seqMax) {
			LOGGER.error("Sequence number wrapped, get a new OSCore context");
			throw new OSException("Sequence number wrapped");
		}
		sender_seq++;
	}

	/**
	 * Checks and sets the sequence number for incoming messages.
	 * 
	 * @param seq the incoming sequence number
	 * 
	 * @throws OSException if the sequence number wraps or if for a replay
	 */
	public synchronized void checkIncomingSeq(int seq) throws OSException {
		if (seq >= seqMax) {
			LOGGER.error("Sequence number wrapped, get new OSCore context");
			throw new OSException(ErrorDescriptions.REPLAY_DETECT);
		}
		rollback_recipient_seq = recipient_seq;
		rollback_recipient_replay = recipient_replay_window;
		if (seq > recipient_seq) {
			// Update the replay window
			int shift = seq - recipient_seq;
			recipient_replay_window = recipient_replay_window << shift;
			recipient_seq = seq;
		} else if (seq == recipient_seq) {
			LOGGER.error("Sequence number is replay");
			throw new OSException(ErrorDescriptions.REPLAY_DETECT);
		} else { // seq < recipient_seq
			if (seq + recipient_replay_window_size < recipient_seq) {
				LOGGER.error("Message too old");
				throw new OSException(ErrorDescriptions.REPLAY_DETECT);
			}
			// seq+replay_window_size > recipient_seq
			int shift = this.recipient_seq - seq;
			int pattern = 1 << shift;
			int verifier = recipient_replay_window & pattern;
			verifier = verifier >> shift;
			if (verifier == 1) {
				throw new OSException(ErrorDescriptions.REPLAY_DETECT);
			}
			recipient_replay_window = recipient_replay_window | pattern;
		}
	}

	/**
	 * Rolls back the latest recipient sequence number update if any
	 */
	public synchronized void rollBack() {
		if (rollback_recipient_replay != -1) {
			recipient_replay_window = rollback_recipient_replay;
			rollback_recipient_replay = -1;
		}
		if (rollback_recipient_seq != -1) {
			recipient_seq = rollback_recipient_seq;
			rollback_recipient_seq = -1;
		}
		if (this.rollback_last_block_tag != null) {
			this.last_block_tag = this.rollback_last_block_tag;
			this.rollback_last_block_tag = null;
		}
	}

	/**
	 * Get IV length in bytes.
	 */
	private static int ivLength(AlgorithmID alg) {
		switch (alg) {
		case AES_CCM_16_64_128:
			return 13;
		default:
			return -1;
		}
	}

	private byte[] deriveKey(byte[] secret, byte[] salt, int cbitKey, String digest, byte[] rgbContext)
			throws CoseException {

		final String HMAC_ALG_NAME = "Hmac" + digest;

		try {
			Mac hmac = Mac.getInstance(HMAC_ALG_NAME);
			int hashLen = hmac.getMacLength();

			// Perform extract
			hmac.init(new SecretKeySpec(salt, HMAC_ALG_NAME));
			byte[] rgbExtract = hmac.doFinal(secret);

			// Perform expand
			hmac.init(new SecretKeySpec(rgbExtract, HMAC_ALG_NAME));
			int c = ((cbitKey + 7) / 8 + hashLen - 1) / hashLen;
			byte[] rgbOut = new byte[cbitKey];
			byte[] T = new byte[hashLen * c];
			byte[] last = new byte[0];
			for (int i = 0; i < c; i++) {
				hmac.reset();
				hmac.update(last);
				hmac.update(rgbContext);
				hmac.update((byte) (i + 1));
				last = hmac.doFinal();
				System.arraycopy(last, 0, T, i * hashLen, hashLen);
			}
			System.arraycopy(T, 0, rgbOut, 0, cbitKey);
			return rgbOut;
		} catch (NoSuchAlgorithmException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (Exception ex) {
			throw new CoseException("Derivation failure", ex);
		}
	}

	/**
	 * Returns this CoAPCode
	 */
	public Code getCoAPCode() {
		return CoAPCode;
	}

	/**
	 * Sets this CoAPCode to CoAPCode
	 */
	public void setCoAPCode(Code CoAPCode) {
		if (CoAPCode != null) {
			this.CoAPCode = CoAPCode;
		}
	}
}
