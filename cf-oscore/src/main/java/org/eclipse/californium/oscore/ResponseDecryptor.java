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

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.cose.Encrypt0Message;
import org.eclipse.californium.elements.util.DatagramReader;

/**
 * 
 * Decrypts an OSCORE encrypted Response.
 *
 */
public class ResponseDecryptor extends Decryptor {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(ResponseDecryptor.class);

	/**
	 * Decrypt the response.
	 *
	 * @param db the context database used
	 * @param response the response
	 * 
	 * @return the decrypted response
	 * 
	 * @throws OSException when decryption fails
	 * 
	 */
	public static Response decrypt(OSCoreCtxDB db, Response response) throws OSException {

		LOGGER.info("Removes E options from outer options which are not allowed there");
		discardEOptions(response);

		byte[] protectedData = response.getPayload();
		Encrypt0Message enc = null;
		Token token = response.getToken();
		OSCoreCtx ctx = null;
		OptionSet uOptions = response.getOptions();

		if (token != null) {
			ctx = db.getContextByToken(token);
			if (ctx == null) {
				LOGGER.error(ErrorDescriptions.TOKEN_INVALID);
				throw new OSException(ErrorDescriptions.TOKEN_INVALID);
			}
			enc = decompression(protectedData, response);
		} else {
			LOGGER.error(ErrorDescriptions.TOKEN_NULL);
			throw new OSException(ErrorDescriptions.TOKEN_NULL);
		}

		// Retrieve Context ID (kid context)
		CBORObject kidContext = enc.findAttribute(CBORObject.FromObject(10));
		byte[] contextID = null;
		if (kidContext != null) {
			contextID = kidContext.GetByteString();
		}

		// Perform context re-derivation procedure if ongoing
		try {
			ctx = ContextRederivation.incomingResponse(db, ctx, contextID);
		} catch (OSException e) {
			LOGGER.error(ErrorDescriptions.CONTEXT_REGENERATION_FAILED);
			throw new OSException(ErrorDescriptions.CONTEXT_REGENERATION_FAILED);
		}

		//Check if parsing of response plaintext succeeds
		try {
			byte[] plaintext = decryptAndDecode(enc, response, ctx, db.getSeqByToken(token));
	
			DatagramReader reader = new DatagramReader(new ByteArrayInputStream(plaintext));
			
			
			response = OptionJuggle.setRealCodeResponse(response,
					CoAP.ResponseCode.valueOf(reader.read(CoAP.MessageFormat.CODE_BITS)));
		
			
			// resets option so eOptions gets priority during parse
			response.setOptions(EMPTY);
			new UdpDataParser().parseOptionsAndPayload(reader, response);
		} catch (Exception e) {
			LOGGER.error(ErrorDescriptions.DECRYPTION_FAILED);
			throw new OSException(ErrorDescriptions.DECRYPTION_FAILED);
		}

		OptionSet eOptions = response.getOptions();
		eOptions = OptionJuggle.merge(eOptions, uOptions);
		response.setOptions(eOptions);

		//Remove token after response is received, unless it has Observe
		//If it has Observe it will be removed after cancellation elsewhere
		if (response.getOptions().hasObserve() == false) {
			db.removeToken(token);
		}

		//Set information about the OSCORE context used in the endpoint context of this response
		OSCoreEndpointContextInfo.receivingResponse(ctx, response);

		return response;
	}
}
