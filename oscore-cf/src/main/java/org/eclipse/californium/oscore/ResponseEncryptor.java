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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.cose.Encrypt0Message;

/**
 * 
 * Encrypts an OSCORE Response.
 *
 */
public class ResponseEncryptor extends Encryptor {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(ResponseEncryptor.class.getName());

	/**
	 * @param r the response
	 * @param ctx the OSCore context
	 * 
	 * @return the response with the encrypted OSCore option
	 * 
	 * @throws OSException when encryption fails
	 */
	public static Response encrypt(Response response, OSCoreCtx ctx, final boolean newPartialIV) throws OSException {

		if (ctx == null) {
			LOGGER.error(ErrorDescriptions.CTX_NULL);
			throw new OSException(ErrorDescriptions.CTX_NULL);
		}

		int realCode = response.getCode().value;
		response = OptionJuggle.setFakeCodeResponse(response);

		OptionSet options = response.getOptions();

		byte[] confidential = OSSerializer.serializeConfidentialData(options, response.getPayload(), realCode);
		byte[] aad = serializeAAD(response, ctx, newPartialIV);
		Encrypt0Message enc = prepareCOSEStructure(confidential, aad);
		byte[] cipherText = encryptAndEncode(enc, ctx, response, newPartialIV);
		compression(ctx, cipherText, response, newPartialIV);

		options = response.getOptions();
		response.setOptions(OptionJuggle.prepareUoptions(options));

		return response;
	}
}
