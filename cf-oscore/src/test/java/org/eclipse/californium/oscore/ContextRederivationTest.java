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
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.SecureRandom;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.ClassRule;
import org.junit.Ignore;
import org.junit.Test;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.cose.AlgorithmID;

/**
 * Class that implements test of functionality for re-derivation of contexts.
 * As detailed in Appendix B.2. of the OSCORE draft:
 * https://tools.ietf.org/html/draft-ietf-core-object-security-16#appendix-B.2
 *
 * This can for instance be used when one device has lost power and information
 * about the mutable parts of a context (e.g. sequence number) but retains information
 * about static parts (e.g. master secret)
 * 
 * To be ran together with the HelloWorldServer
 */
public class ContextRederivationTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);
	
	private static String SERVER_RESPONSE = "Hello World!";
	
	private final static HashMapCtxDB db = HashMapCtxDB.getInstance();
	private final static String uriLocal = "coap://localhost";
	private final static String hello1 = "/hello/1";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// test vector OSCORE draft Appendix C.1.1
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] sid = new byte[0];
	private final static byte[] rid = new byte[] { 0x01 };
	
	/**
	 * Test context re-derivation followed by a normal message exchange.
	 * 
	 * @throws OSException
	 * @throws ConnectorException
	 * @throws IOException
	 */
	@Ignore
	@Test
	public void rederivationTest() throws OSException, ConnectorException, IOException {
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null);
		db.addContext(uriLocal, ctx);
		OSCoreCoapStackFactory.useAsDefault();

		rederive(uriLocal);
		
		CoapClient c = new CoapClient(uriLocal + hello1);
		Request r = new Request(Code.GET);
		r.getOptions().setOscore(new byte[0]);
		System.out.println((Utils.prettyPrint(r)));
		
		CoapResponse resp = c.advanced(r);
		System.out.println((Utils.prettyPrint(resp)));
		
		assertEquals(resp.getCode(), ResponseCode.CONTENT);
		assertEquals(resp.getResponseText(), SERVER_RESPONSE);
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
	public static void rederive(String uriLocal) throws ConnectorException, IOException, OSException {
		//Generate a random 8 byte Context ID
		SecureRandom random = new SecureRandom();
		byte[] newContextId = new byte[8];
		random.nextBytes(newContextId);
		
		//Create new context with the generated Context ID
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, newContextId);
		ctx.setIncludeContextId(true);
		db.addContext(uriLocal, ctx);
		OSCoreCoapStackFactory.useAsDefault();
		
		//Now send request using the new context
		String resource = "/rederive"; //Dummy resource to access for context re-derivation
		String URI = uriLocal + resource;
		System.out.println(URI);
		OSCoreCoapStackFactory.useAsDefault();
		
		CoapClient c = new CoapClient(URI);
		Request r = new Request(Code.GET);
		r.getOptions().setOscore(new byte[0]);
		System.out.println(Utils.prettyPrint(r));
		
		CoapResponse resp = null;
		resp = c.advanced(r);
		System.out.println(Utils.prettyPrint(resp));
	}
	
}
