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
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.auth.OSCorePeerIdentity;

/**
 * Class that handles the EndpointContext for OSCORE messages. 
 *
 * It provides functionality to set an appropriate OSCORE peer identity
 * for an EndpointContext.
 *
 */
public class OSCorePeerIdentityHandler {

	/**
	 * Updates the currently set endpoint contexts adding an OSCORE peer identity.
	 * Will only update endpoint contexts that are set as type AddressEndpointContext
	 * and have an empty or OSCORE peer identity.
	 * 
	 * If for instance Scandium has set another type of EndpointContext or another
	 * type of Principal as peer identity it will not be updated.
	 * 
	 * @param oscoreCtx the OSCORE context used for this message
	 * @param message the message to set the endpoint context for
	 */
	public static void setPeerIdentity(OSCoreCtx oscoreCtx, Message message) {

		//Create a new OSCORE peer identity
		OSCorePeerIdentity newPeerIdentity = new OSCorePeerIdentity(oscoreCtx.getUri(),
				oscoreCtx.getIdContext(), oscoreCtx.getRecipientId(), oscoreCtx.getSenderId());

		//Set updated destination context with new OSCORE peer identity
		EndpointContext dstContext = message.getDestinationContext();
		if(dstContext instanceof AddressEndpointContext &&
				(dstContext.getPeerIdentity() == null || dstContext.getPeerIdentity() instanceof OSCorePeerIdentity)) {

			AddressEndpointContext newContext = new AddressEndpointContext(dstContext.getPeerAddress(),
					dstContext.getVirtualHost(), newPeerIdentity);

			message.setDestinationContext(newContext);
		}

		//Set updated source context with new OSCORE peer identity
		EndpointContext srcContext = message.getSourceContext();
		if(srcContext instanceof AddressEndpointContext &&
				(srcContext.getPeerIdentity() == null || srcContext.getPeerIdentity() instanceof OSCorePeerIdentity)) {

			AddressEndpointContext newContext = new AddressEndpointContext(srcContext.getPeerAddress(),
					srcContext.getVirtualHost(), newPeerIdentity);

			message.setSourceContext(newContext);
		}

	}

}
