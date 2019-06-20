/*******************************************************************************
 * Copyright (c) 2019 RISE SICS and others.
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
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.io.IOException;
import java.security.SecureRandom;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.Bytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class that implements methods for dynamic re-generation of OSCORE contexts.
 *
 * See https://tools.ietf.org/html/draft-ietf-core-object-security-16#appendix-B.2
 *
 */
public class ContextRederivation {
	
	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(RequestDecryptor.class.getName());
	
	/**
	 * Method for an application to indicate that the mutable parts of an OSCORE context has been lost.
	 * In such case the context re-derivation procedure is triggered.
	 * 
	 * @param uri the URI associated with the context information has been lost for
	 * @throws CoapOSException if re-generation of the context fails
	 */
	public static void setLostContext(String uri) throws CoapOSException
	{
		try {
			rederive(uri);
		} catch (ConnectorException | IOException | OSException e) {
			LOGGER.error(ErrorDescriptions.CONTEXT_REGENERATION_FAILED);
			throw new CoapOSException(ErrorDescriptions.CONTEXT_REGENERATION_FAILED, ResponseCode.BAD_REQUEST);
		}
	}
	
	/**
	 * Perform re-derivation of contexts as detailed in Appendix B.2.
	 * Essentially it uses a message exchange together with the Context ID
	 * field in the OSCORE option to securely generate a new shared context.
	 * 
	 * @throws IOException 
	 * @throws ConnectorException 
	 * @throws OSException 
	 */
	private static void rederive(String uri) throws ConnectorException, IOException, OSException {
		//Generate a random 8 byte Context ID
		SecureRandom random = new SecureRandom();
		byte[] newContextId = new byte[8];
		random.nextBytes(newContextId);
		
		//Retrieve the context for the target URI
		HashMapCtxDB db = HashMapCtxDB.getInstance();
		OSCoreCtx oldCtx = db.getContext(uri);
		
		//Create new context with the generated Context ID
		OSCoreCtx ctx = new OSCoreCtx(oldCtx.getMasterSecret(), true, oldCtx.getAlg(), oldCtx.getSenderId(),
				oldCtx.getRecipientId(), oldCtx.getKdf(), oldCtx.getRecipientReplaySize(), oldCtx.getSalt(), newContextId);
		ctx.setIncludeContextId(true);
		db.addContext(uri, ctx);
		
		//Now send request using the new context
		String resource = "/rederive"; //Dummy resource to access for context re-derivation
		String URI = uri + resource;
		System.out.println(URI);
		
		CoapClient c = new CoapClient(URI);
		Request r = new Request(Code.GET);
		r.getOptions().setOscore(Bytes.EMPTY);
		System.out.println(Utils.prettyPrint(r));
		
		CoapResponse resp = null;
		resp = c.advanced(r);
		System.out.println(Utils.prettyPrint(resp));
		c.shutdown();
	}
	
}
