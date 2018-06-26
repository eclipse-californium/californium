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

import java.io.ByteArrayInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.serialization.DataParser;
import org.eclipse.californium.cose.Encrypt0Message;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OptionJuggle;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.HeaderKeys;

/**
 * 
 * Decrypts an OSCORE encrypted Request.
 *
 */
public class RequestDecryptor extends Decryptor {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(RequestDecryptor.class.getName());

	/**
	 * @param request the request to decrypt
	 * @param db the database of OSCore contexts
	 * 
	 * @return the cid of the OSCore context use for this request
	 * 
	 * @throws OSException if decryption fails
	 */
	public static Request decrypt(Request request) throws CoapOSException {

		discardEOptions(request);

		OSCoreCtxDB db = HashMapCtxDB.getInstance();
		byte[] protectedData = request.getPayload();
		Encrypt0Message enc;
		OptionSet uOptions = request.getOptions();
		try {
			enc = decompression(protectedData, request);
		} catch (OSException e) {
			LOGGER.error(Error.FAILED_TO_DECODE_COSE);
			throw new CoapOSException(Error.FAILED_TO_DECODE_COSE, ResponseCode.BAD_OPTION);
		}

		CBORObject kid = enc.findAttribute(HeaderKeys.KID);
		if (kid == null || !kid.getType().equals(CBORType.ByteString)) {
			LOGGER.error(Error.MISSING_KID);
			throw new CoapOSException(Error.FAILED_TO_DECODE_COSE, ResponseCode.BAD_OPTION);
		}
		byte[] rid = kid.GetByteString();

		OSCoreCtx ctx = db.getContext(rid);

		if (ctx == null) {
			LOGGER.error(Error.CONTEXT_NOT_FOUND);
			throw new CoapOSException(Error.CONTEXT_NOT_FOUND, ResponseCode.UNAUTHORIZED);
		}

		byte[] plaintext;
		try {
			plaintext = decryptAndDecode(enc, request, ctx, null);
		} catch (OSException e) {
			LOGGER.error(Error.DECRYPTION_FAILED);
			throw new CoapOSException(Error.DECRYPTION_FAILED, ResponseCode.BAD_REQUEST);
		}

		DatagramReader reader = new DatagramReader(new ByteArrayInputStream(plaintext));
		ctx.setCoAPCode(Code.valueOf(reader.read(CoAP.MessageFormat.CODE_BITS)));
		// resets option so eOptions gets priority during parse
		request.setOptions(EMPTY);
		DataParser.parseOptionsAndPayload(reader, request);
		OptionSet eOptions = request.getOptions();
		eOptions = OptionJuggle.merge(eOptions, uOptions);

		request.setOptions(eOptions);

		// We need the kid value on layer level
		request.getOptions().setOscore(rid);
		return OptionJuggle.setRealCodeRequest(request, ctx.getCoAPCode());
	}
}
