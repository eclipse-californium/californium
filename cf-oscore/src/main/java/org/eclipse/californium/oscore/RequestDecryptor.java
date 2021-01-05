/*******************************************************************************
 * Copyright (c) 2019 RISE SICS and others.
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
 *    Joakim Brorsson
 *    Ludwig Seitz (RISE SICS)
 *    Tobias Andersson (RISE SICS)
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.io.ByteArrayInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.cose.Encrypt0Message;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.elements.util.DatagramReader;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.HeaderKeys;

/**
 * 
 * Decrypts an OSCORE encrypted Request.
 *
 */
public class RequestDecryptor extends Decryptor {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(RequestDecryptor.class);

	/**
	 * @param db the context database used
	 * @param request the request to decrypt
	 * @param ctx the OSCore context
	 * 
	 * @return the decrypted request
	 * 
	 * @throws CoapOSException if decryption fails
	 */
	public static Request decrypt(OSCoreCtxDB db, Request request, OSCoreCtx ctx) throws CoapOSException {

		LOGGER.info("Removes E options from outer options which are not allowed there");
		discardEOptions(request);

		byte[] protectedData = request.getPayload();
		Encrypt0Message enc;
		OptionSet uOptions = request.getOptions();
		try {
			enc = decompression(protectedData, request);
		} catch (OSException e) {
			LOGGER.error(ErrorDescriptions.FAILED_TO_DECODE_COSE);
			throw new CoapOSException(ErrorDescriptions.FAILED_TO_DECODE_COSE, ResponseCode.BAD_OPTION);
		}

		CBORObject kid = enc.findAttribute(HeaderKeys.KID);
		if (kid == null || !kid.getType().equals(CBORType.ByteString)) {
			LOGGER.error(ErrorDescriptions.MISSING_KID);
			throw new CoapOSException(ErrorDescriptions.FAILED_TO_DECODE_COSE, ResponseCode.BAD_OPTION);
		}
		byte[] rid = kid.GetByteString();

		// Retrieve Context ID (kid context)
		CBORObject kidContext = enc.findAttribute(CBORObject.FromObject(10));
		byte[] contextID = null;
		if (kidContext != null) {
			contextID = kidContext.GetByteString();
		}

		// Perform context re-derivation procedure if triggered or ongoing
		try {
			ctx = ContextRederivation.incomingRequest(db, ctx, contextID, rid);
		} catch (OSException e) {
			LOGGER.error(ErrorDescriptions.CONTEXT_REGENERATION_FAILED);
			throw new CoapOSException(ErrorDescriptions.CONTEXT_REGENERATION_FAILED, ResponseCode.BAD_REQUEST);
		}

		if (ctx == null) {
			LOGGER.error(ErrorDescriptions.CONTEXT_NOT_FOUND);
			throw new CoapOSException(ErrorDescriptions.CONTEXT_NOT_FOUND, ResponseCode.UNAUTHORIZED);
		}

		byte[] plaintext;
		try {
			plaintext = decryptAndDecode(enc, request, ctx, null);
		} catch (OSException e) {
			//First check for replay exceptions
			if (e.getMessage().equals(ErrorDescriptions.REPLAY_DETECT)) { 
				LOGGER.error(ErrorDescriptions.REPLAY_DETECT);
				throw new CoapOSException(ErrorDescriptions.REPLAY_DETECT, ResponseCode.UNAUTHORIZED);
			}
			//Otherwise return generic error message
			LOGGER.error(ErrorDescriptions.DECRYPTION_FAILED);
			throw new CoapOSException(ErrorDescriptions.DECRYPTION_FAILED, ResponseCode.BAD_REQUEST);
		}
		
		//Check if parsing of request plaintext succeeds
		try {
			DatagramReader reader = new DatagramReader(new ByteArrayInputStream(plaintext));
			ctx.setCoAPCode(Code.valueOf(reader.read(CoAP.MessageFormat.CODE_BITS)));
			// resets option so eOptions gets priority during parse
			request.setOptions(EMPTY);
			new UdpDataParser().parseOptionsAndPayload(reader, request);
		} catch (Exception e) {
			LOGGER.error(ErrorDescriptions.DECRYPTION_FAILED);
			throw new CoapOSException(ErrorDescriptions.DECRYPTION_FAILED, ResponseCode.BAD_REQUEST);
		}
			
		OptionSet eOptions = request.getOptions();
		eOptions = OptionJuggle.merge(eOptions, uOptions);	
		request.setOptions(eOptions);

		// We need the kid value on layer level
		request.getOptions().setOscore(rid);

		// Associate the Token with the context used
		db.addContext(request.getToken(), ctx);

		//Set information about the OSCORE context used in the endpoint context of this request
		OSCoreEndpointContextInfo.receivingRequest(ctx, request);

		return OptionJuggle.setRealCodeRequest(request, ctx.getCoAPCode());
	}
}
