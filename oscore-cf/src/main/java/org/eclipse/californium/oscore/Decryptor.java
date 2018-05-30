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
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.nio.ByteBuffer;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.cose.Encrypt0Message;

import com.upokecenter.cbor.CBORObject;

import COSE.Attribute;
import COSE.CoseException;
import COSE.HeaderKeys;

/**
 * 
 * Gathers generalized methods for decryption and decompression of OSCORE
 * protected messages. Also provides decoding of the encoded OSCORE option
 *
 */
public abstract class Decryptor {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(Decryptor.class.getName());

	protected static final OptionSet EMPTY = new OptionSet();

	/**
	 * Decrypts and decodes the message.
	 * 
	 * @param enc the COSE structure
	 * @param message the message
	 * @param ctx the OSCore context
	 * @param seqByToken the sequence number
	 * 
	 * @return the decrypted plaintext
	 *
	 * @throws OSException if decryption or decoding fails
	 */
	protected static byte[] decryptAndDecode(Encrypt0Message enc, Message message, OSCoreCtx ctx, Integer seqByToken)
			throws OSException {
		int seq = -2;
		boolean isRequest = message instanceof Request;
		byte[] nonce = null;
		byte[] partialIV = null;

		if (isRequest) {

			CBORObject tmp = enc.findAttribute(HeaderKeys.PARTIAL_IV);

			if (tmp == null) {
				LOGGER.error("Decryption failed: no partialIV in request");
				throw new OSException(ErrorDescriptions.DECRYPTION_FAILED);
			} else {

				partialIV = tmp.GetByteString();
				partialIV = expandToIntSize(partialIV);
				seq = ByteBuffer.wrap(partialIV).getInt();
				ctx.checkIncomingSeq(seq);

				nonce = OSSerializer.nonceGeneration(partialIV, ctx.getRecipientId(), ctx.getCommonIV(),
						ctx.getIVLength());
			}
		} else {
			if (seqByToken == null) {
				LOGGER.error("Decryption failed: the arrived response is not connected to a request we sent");
				throw new OSException(ErrorDescriptions.DECRYPTION_FAILED);
			}

			CBORObject tmp = enc.findAttribute(HeaderKeys.PARTIAL_IV);

			if (tmp == null) {

				// this should use the partialIV that arrived in the request and
				// not the response
				seq = seqByToken;
				nonce = OSSerializer.nonceGeneration(ByteBuffer.allocate(Integer.BYTES).putInt(seqByToken).array(),
						ctx.getSenderId(), ctx.getCommonIV(), ctx.getIVLength());
			} else {

				partialIV = tmp.GetByteString();
				partialIV = expandToIntSize(partialIV);
				seq = ByteBuffer.wrap(partialIV).getInt();
				nonce = OSSerializer.nonceGeneration(partialIV, ctx.getRecipientId(), ctx.getCommonIV(),
						ctx.getIVLength());
			}
		}

		byte[] plaintext = null;
		byte[] key = ctx.getRecipientKey();
		byte[] aad = serializeAAD(message, ctx, seq);

		enc.setExternal(aad);
		try {

			enc.addAttribute(HeaderKeys.Algorithm, ctx.getAlg().AsCBOR(), Attribute.DO_NOT_SEND);
			enc.addAttribute(HeaderKeys.IV, CBORObject.FromObject(nonce), Attribute.DO_NOT_SEND);
			plaintext = enc.decrypt(key);

		} catch (CoseException e) {
			LOGGER.error(ErrorDescriptions.DECRYPTION_FAILED + " " + e.getMessage());
			throw new OSException(ErrorDescriptions.DECRYPTION_FAILED + " " + e.getMessage());
		}

		return plaintext;
	}

	private static byte[] expandToIntSize(byte[] partialIV) throws OSException {
		if (partialIV.length > Integer.BYTES) {
			LOGGER.error("The partial IV is: " + partialIV.length + " long, " + Integer.BYTES + " was expected");
			throw new OSException("Partial IV too long");
		} else if (partialIV.length == Integer.BYTES) {
			return partialIV;
		}
		byte[] ret = new byte[Integer.BYTES];
		for (int i = 0; i < partialIV.length; i++) {
			ret[Integer.BYTES - partialIV.length + i] = partialIV[i];
		}
		return ret;

	}

	/**
	 * @param protectedData the protected data to decrypt
	 * @return the COSE structure
	 */
	protected static Encrypt0Message prepareCOSEStructure(byte[] protectedData) {
		Encrypt0Message enc = new Encrypt0Message(false, true);
		try {
			enc.DecodeFromCBORObject(CBORObject.DecodeFromBytes(protectedData));
		} catch (CoseException e) {
			e.printStackTrace();
		}
		return enc;
	}

	/**
	 * Prepare the AAD.
	 * 
	 * @param message the message
	 * @param ctx the OSCore context
	 * @param seq the sequence number
	 * 
	 * @return the serialized AAD
	 */
	protected static byte[] serializeAAD(Message message, OSCoreCtx ctx, int seq) {
		if (message instanceof Request) {
			Request r = (Request) message;
			return OSSerializer.serializeReceiveRequestAAD(CoAP.VERSION, seq, ctx, r.getOptions());
		} else if (message instanceof Response) {
			Response r = (Response) message;
			return OSSerializer.serializeReceiveResponseAAD(CoAP.VERSION, seq, ctx, r.getOptions());
		}
		return null;
	}

	/**
	 * Decompress the message.
	 * 
	 * @param cipherText the encrypted data
	 * @param message the received message
	 * @return the Encrypt0Message
	 * @throws OSException
	 */
	protected static Encrypt0Message decompression(byte[] cipherText, Message message) throws OSException {
		Encrypt0Message enc = new Encrypt0Message(false, true);

		decodeObjectSecurity(message, enc);

		if (cipherText != null)
			enc.setEncryptedContent(cipherText);
		return enc;
	}

	/**
	 * Decodes the Object-Security value.
	 * 
	 * @param message the received message
	 * @param enc the Encrypt0Message object
	 * @throws OSException
	 */
	private static void decodeObjectSecurity(Message message, Encrypt0Message enc) throws OSException {
		byte[] total = message.getOptions().getOscore();

		byte flagByte = total[0];

		int n = flagByte & 0x07;
		int k = flagByte & 0x08;
		int h = flagByte & 0xa6;

		byte[] partialIV = null;
		byte[] kid = null;
		int index = 1;

		if (n > 0) {
			try {
				partialIV = Arrays.copyOfRange(total, index, index + n);
				index += n;
			} catch (Exception e) {
				LOGGER.error("Partial_IV is missing from message when it is expected.");
				throw new OSException(ErrorDescriptions.FAILED_TO_DECODE_COSE);
			}
		}

		if (h == 16) {
			int s = total[index];
			index += 1;

			if (s > 0) {
				LOGGER.error("Kidcontext is included, but it is not supported. We ignore it and continue processing.");
			} else {
				LOGGER.error("Kid context is missing from message when it is expected.");
				throw new OSException(ErrorDescriptions.FAILED_TO_DECODE_COSE);
			}
		}

		if (k == 8) {
			kid = Arrays.copyOfRange(total, index, total.length);
		} else {
			if (message instanceof Request) {
				LOGGER.error("Kid is missing from message when it is expected.");
				throw new OSException(ErrorDescriptions.FAILED_TO_DECODE_COSE);
			}
		}

		try {
			if (partialIV != null)
				enc.addAttribute(HeaderKeys.PARTIAL_IV, CBORObject.FromObject(partialIV), Attribute.UNPROTECTED);
			if (kid != null)
				enc.addAttribute(HeaderKeys.KID, CBORObject.FromObject(kid), Attribute.UNPROTECTED);
		} catch (CoseException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Replaces the message's options with a new OptionSet which doesn't contain
	 * any of the non-special E options as outer options
	 * 
	 * @param message
	 */
	protected static void discardEOptions(Message message) {
		OptionSet newOptions = OptionJuggle.discardEOptions(message.getOptions());
		message.setOptions(newOptions);
	}
}
