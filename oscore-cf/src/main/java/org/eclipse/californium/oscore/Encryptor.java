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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
 * Gathers generalized methods for encryption and compression of OSCORE
 * protected messages. Also encodes the OSCORE option.
 *
 */
public abstract class Encryptor {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(Encryptor.class.getName());

	/**
	 * Encrypt the COSE message using the OSCore context.
	 * 
	 * @param enc the encrypt structure
	 * @param ctx the OSCore context
	 * @param mess the message
	 *
	 * @return the COSE message
	 * 
	 * @throws OSException if encryption or encoding fails
	 */
	protected static byte[] encryptAndEncode(Encrypt0Message enc, OSCoreCtx ctx, Message mess, boolean newPartialIV)
			throws OSException {
		boolean isRequest = mess instanceof Request;

		try {
			byte[] key = ctx.getSenderKey();
			byte[] partialIV = null;
			byte[] nonce = null;

			if (isRequest) {
				partialIV = OSSerializer.processPartialIV(ctx.getSenderSeq());
				nonce = OSSerializer.nonceGeneration(partialIV, ctx.getSenderId(), ctx.getCommonIV(),
						ctx.getIVLength());
				enc.addAttribute(HeaderKeys.PARTIAL_IV, CBORObject.FromObject(partialIV), Attribute.UNPROTECTED);
				enc.addAttribute(HeaderKeys.KID, CBORObject.FromObject(ctx.getSenderId()), Attribute.UNPROTECTED);
			} else {

				if (!newPartialIV) {
					// use nonce from request
					partialIV = OSSerializer.processPartialIV(ctx.getReceiverSeq());
					nonce = OSSerializer.nonceGeneration(partialIV, ctx.getRecipientId(), ctx.getCommonIV(),
							ctx.getIVLength());
				} else {
					// response' creates its own partialIV
					partialIV = OSSerializer.processPartialIV(ctx.getSenderSeq());
					nonce = OSSerializer.nonceGeneration(partialIV, ctx.getRecipientId(), ctx.getCommonIV(),
							ctx.getIVLength());
				}
			}

			enc.addAttribute(HeaderKeys.IV, CBORObject.FromObject(nonce), Attribute.DO_NOT_SEND);
			enc.addAttribute(HeaderKeys.Algorithm, ctx.getAlg().AsCBOR(), Attribute.DO_NOT_SEND);
			enc.encrypt(key);

			return enc.getEncryptedContent();
		} catch (CoseException e) {
			LOGGER.error("COSE/Crypto exception: " + e.getMessage());
			throw new OSException(e.getMessage());
		}
	}

	/**
	 * Serialize the Additional Authenticated Data (AAD).
	 * 
	 * @param m the message
	 * @param ctx the OSCore context
	 * @return the serialized AAD
	 */
	protected static byte[] serializeAAD(Message m, OSCoreCtx ctx, final boolean newPartialIV) {
		if (m instanceof Request) {
			Request r = (Request) m;
			return OSSerializer.serializeSendRequestAAD(CoAP.VERSION, ctx, r.getOptions());
		} else if (m instanceof Response) {
			Response r = (Response) m;
			return OSSerializer.serializeSendResponseAAD(CoAP.VERSION, ctx, r.getOptions(), newPartialIV);
		}
		return null;
	}

	/**
	 * Initiates the encrypt0message object and sets the confidential (plaintext
	 * to be encrypted) and the aad.
	 * 
	 * @param confidential the plaintext to be encrypted
	 * @param aad the aad
	 * @return the intiated and prepared encrypt0message object
	 */
	protected static Encrypt0Message prepareCOSEStructure(byte[] confidential, byte[] aad) {
		Encrypt0Message enc = new Encrypt0Message(false, true);
		enc.SetContent(confidential);
		enc.setExternal(aad);
		return enc;
	}

	/**
	 * Compresses the message by encoding the Object-Security value and sets the
	 * message's payload to the cipherText.
	 * 
	 * @param ctx the OSCoreCtx
	 * @param cipherText the cipher text to be appended to this compression
	 * @param message the message
	 * @return the entire message's byte array
	 */
	protected static byte[] compression(OSCoreCtx ctx, byte[] cipherText, Message message, final boolean newPartialIV) {
		boolean request = message instanceof Request;
		ByteArrayOutputStream bRes = new ByteArrayOutputStream();
		OptionSet options = message.getOptions();
		options.removeOscore();

		if (request) {
			message.getOptions().setOscore(encodeOSCoreRequest(ctx));
		} else {
			message.getOptions().setOscore(encodeOSCoreResponse(ctx, newPartialIV));
		}

		if (cipherText != null) {
			message.setPayload(cipherText);
		}

		return bRes.toByteArray();
	}

	/**
	 * Encodes the Object-Security value for a Request.
	 * 
	 * @param ctx the context
	 * @return the Object-Security value as byte array
	 */
	public static byte[] encodeOSCoreRequest(OSCoreCtx ctx) {
		int firstByte = 0x00;
		ByteArrayOutputStream bRes = new ByteArrayOutputStream();
		byte[] partialIV = OSSerializer.processPartialIV(ctx.getSenderSeq());
		firstByte = firstByte | (partialIV.length & 0x07);
		firstByte = firstByte | 0x08;

		bRes.write(firstByte);
		try {
			bRes.write(partialIV);
			bRes.write(ctx.getSenderId());
		} catch (IOException e) {
			e.printStackTrace();
		}
		return bRes.toByteArray();
	}

	/**
	 * Encodes the Object-Security value for a Response.
	 * 
	 * @param ctx the context
	 * @param hasObserve if true encodes the partialIV, otherwise partialIV is
	 *            not encoded
	 * @return
	 */
	public static byte[] encodeOSCoreResponse(OSCoreCtx ctx, final boolean newPartialIV) {
		int firstByte = 0x00;
		ByteArrayOutputStream bRes = new ByteArrayOutputStream();

		if (newPartialIV) {
			byte[] partialIV = OSSerializer.processPartialIV(ctx.getSenderSeq());
			firstByte = firstByte | (partialIV.length & 0x07);
			bRes.write(firstByte);
			try {
				bRes.write(partialIV);
			} catch (IOException e) {
				e.printStackTrace();
			}
		} else {
			bRes.write(firstByte);
			return bRes.toByteArray();
		}
		return bRes.toByteArray();
	}
}
