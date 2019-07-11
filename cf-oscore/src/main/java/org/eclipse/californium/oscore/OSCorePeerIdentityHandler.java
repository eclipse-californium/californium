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

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.auth.OSCorePeerIdentity;

/**
 * Class that handles the EndpointContext for OSCORE messages. 
 *
 * It provides functionality to set an appropriate OSCORE peer identity
 * for an EndpointContext.
 *
 * Will only add a peer identity for endpoint contexts that have
 * an empty or OSCORE peer identity. If for instance Scandium has
 * set another type of Principal as peer identity it will not be updated.
 *
 */
public class OSCorePeerIdentityHandler {

	/**
	 * Sets destination endpoint context for outgoing requests with an OSCORE peer identity.
	 *
	 * @param oscoreCtx the OSCORE context used for this message
	 * @param request the request to set the endpoint context for
	 */
	public static void sendingRequest(OSCoreCtx oscoreCtx, Request request) {
		setPeerIdentityOutgoing(oscoreCtx, request);
	}

	/**
	 * Sets source endpoint context for incoming requests with an OSCORE peer identity.
	 *
	 * @param oscoreCtx the OSCORE context used for this message
	 * @param request the request to set the endpoint context for
	 */
	public static void receivingRequest(OSCoreCtx oscoreCtx, Request request) {
		setPeerIdentityIncoming(oscoreCtx, request);
	}

	/**
	 * Sets destination endpoint context for outgoing responses with an OSCORE peer identity.
	 *
	 * @param oscoreCtx the OSCORE context used for this message
	 * @param response the response to set the endpoint context for
	 */
	public static void sendingResponse(OSCoreCtx oscoreCtx, Response response) {
		setPeerIdentityOutgoing(oscoreCtx, response);
	}

	/**
	 * Sets destination endpoint context for incoming responses with an OSCORE peer identity.
	 *
	 * @param oscoreCtx the OSCORE context used for this message
	 * @param response the response to set the endpoint context for
	 */
	public static void receivingResponse(OSCoreCtx oscoreCtx, Response response) {
		setPeerIdentityIncoming(oscoreCtx, response);
	}

	/**
	 * Updates the currently set destination endpoint context for outgoing
	 * messages adding an OSCORE peer identity.
	 *
	 * @param oscoreCtx the OSCORE context used for this message
	 * @param message the message to set the destination endpoint context for
	 */
	private static void setPeerIdentityOutgoing(OSCoreCtx oscoreCtx, Message message) {
		//Create a new OSCORE peer identity
		OSCorePeerIdentity newPeerIdentity = new OSCorePeerIdentity(oscoreCtx.getUri(),
				oscoreCtx.getIdContext(), oscoreCtx.getRecipientId(), oscoreCtx.getSenderId());

		//Set updated destination context with new OSCORE peer identity
		EndpointContext dstContext = message.getDestinationContext();
		if(dstContext != null &&
				(dstContext.getPeerIdentity() == null || dstContext.getPeerIdentity() instanceof OSCorePeerIdentity)) {

			AddressEndpointContext newContext = new AddressEndpointContext(dstContext.getPeerAddress(),
					dstContext.getVirtualHost(), newPeerIdentity);

			message.setDestinationContext(newContext);
		}
	}

	/**
	 * Updates the currently set source endpoint context for incoming
	 * messages adding an OSCORE peer identity.
	 *
	 * @param oscoreCtx the OSCORE context used for this message
	 * @param message the message to set the source endpoint context for
	 */
	private static void setPeerIdentityIncoming(OSCoreCtx oscoreCtx, Message message) {
		//Create a new OSCORE peer identity
		OSCorePeerIdentity newPeerIdentity = new OSCorePeerIdentity(oscoreCtx.getUri(),
				oscoreCtx.getIdContext(), oscoreCtx.getRecipientId(), oscoreCtx.getSenderId());

		//Set updated source context with new OSCORE peer identity
		EndpointContext srcContext = message.getSourceContext();
		if(srcContext != null &&
				(srcContext.getPeerIdentity() == null || srcContext.getPeerIdentity() instanceof OSCorePeerIdentity)) {

			AddressEndpointContext newContext = new AddressEndpointContext(srcContext.getPeerAddress(),
					srcContext.getVirtualHost(), newPeerIdentity);

			message.setSourceContext(newContext);
		}
	}
}
