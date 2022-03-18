/*******************************************************************************
 * Copyright (c) 2022 RISE and others.
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
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/
package org.eclipse.californium.plugtests.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.*;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCtx;

/**
 * Defines a resource that gives the latest security material for OSCORE. This
 * is useful as the replay window will continuously shift and the ID Context can
 * change due to execution of the Appendix B.2 context rederivation procedure.
 * If someone wants to reach the OSCORE resource with a client not supporting
 * Appendix B.2 they will need this information.
 *
 */
public class OscoreInfo extends CoapResource {

	private HashMapCtxDB db;
	private byte[] serverRid;

	public OscoreInfo(HashMapCtxDB db, byte[] serverRid) {
		super("oscoreInfo", true);
		getAttributes().setTitle("Resource for retreiving the OSCORE security material used by this server");

		this.db = db;
		this.serverRid = serverRid;
	}
	

	@Override
	public void handleGET(CoapExchange exchange) {

		StringBuilder payload = new StringBuilder();

		// Provide information from the current OSCORE context of the server

		OSCoreCtx serverCtx = db.getContext(serverRid);

		payload.append("\nExpected OSCORE configuration: ");
		payload.append("\n(Usage of Appendix B.2 is also possible) ");

		payload.append("\nID Context: ");
		payload.append(Utils.toHexString(serverCtx.getIdContext()));

		int replayWindow = serverCtx.getRecipientReplayWindow();
		int offset = serverCtx.getRecipientReplaySize() - Integer.numberOfLeadingZeros(replayWindow);
		payload.append("\nClient Sender Sequence Number: ");
		payload.append(serverCtx.getLowestRecipientSeq() + offset);

		// complete the request
		exchange.setMaxAge(30);
		exchange.respond(CONTENT, payload.toString(), TEXT_PLAIN);
	}
}
