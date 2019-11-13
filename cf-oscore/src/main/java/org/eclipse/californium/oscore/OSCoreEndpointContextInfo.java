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
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.EndpointContextOperator;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;

/**
 * Class that handles setting information in an EndpointContext for OSCORE
 * messages.
 *
 * It provides functionality to set appropriate information about the OSCORE
 * context used, as strings in the map inside an EndpointContext.
 *
 * When an application is receiving a message or sending a request it can use
 * the strings in the EndpointContext to retrieve information about what OSCORE
 * context was used for this messages.
 *
 * Information that can be retrieved is the URI associated to the OSCORE
 * context, the Sender ID, Recipient ID and Context ID of the OSCORE context.
 *
 * This class contains methods to set the source endpoint context for incoming
 * messages. It also contains a method that adds an operator on the exchange
 * when sending a request that will make the new created destination endpoint
 * context available via a callback. For outgoing responses the destination
 * endpoint context used will be the source endpoint context created for the
 * incoming request.
 */
public class OSCoreEndpointContextInfo {

	/**
	 * Defines strings for the keys to be set in the EndpointContext.
	 */

	private final static String PREFIX = MapBasedEndpointContext.KEY_PREFIX_NONE_CRITICAL;

	public final static String OSCORE_SENDER_ID = PREFIX + "OSCORE_SENDER_ID";

	public final static String OSCORE_RECIPIENT_ID = PREFIX + "OSCORE_RECIPIENT_ID";

	public final static String OSCORE_CONTEXT_ID = PREFIX + "OSCORE_CONTEXT_ID";

	public final static String OSCORE_URI = PREFIX + "OSCORE_URI";

	/**
	 * Sets information in a destination endpoint context for outgoing requests.
	 *
	 * Sending a request is a special case since an operator should be added to
	 * the exchange that sets the appropriate information in the endpoint
	 * context that will be created after the request is sent.
	 *
	 * @param oscoreCtx the OSCORE context used for this message
	 * @param exchange the exchange to later set the endpoint context for
	 */
	public static void sendingRequest(OSCoreCtx oscoreCtx, Exchange exchange) {
		exchange.setEndpointContextPreOperator(new OSCoreEndpointContextOperator(oscoreCtx));
	}

	/**
	 * Class that functions as an operator on the exchange. It will set
	 * information about the OSCORE context used on the new endpoint context
	 * created after the request is sent.
	 *
	 * This new endpoint context is available using
	 * MessageObserver.onContextEstablished(EndpointContext).
	 *
	 */
	private static class OSCoreEndpointContextOperator implements EndpointContextOperator {

		/**
		 * OSCORE context to take information from to set in the endpoint
		 * context
		 */
		private final OSCoreCtx oscoreCtx;

		/**
		 * Constructor taking an OSCORE Context that the information to be set
		 * in the endpoint context will be taken from.
		 *
		 * @param oscoreCtx the OSCORE context to take information to set from
		 */
		public OSCoreEndpointContextOperator(final OSCoreCtx oscoreCtx) {
			this.oscoreCtx = oscoreCtx;
		}

		/**
		 * Method that will be ran when setting the endpoint context for an
		 * exchange. Should perform changes to the endpoint context to add the
		 * OSCORE-related strings.
		 *
		 * @return the new endpoint context to use
		 */
		@Override
		public EndpointContext apply(EndpointContext context) {
			return setInfo(oscoreCtx, context);
		}

	}

	/**
	 * Sets information in a source endpoint context for incoming requests.
	 *
	 * @param oscoreCtx the OSCORE context used for this message
	 * @param request the request to set the endpoint context for
	 */
	public static void receivingRequest(OSCoreCtx oscoreCtx, Request request) {
		setInfoIncoming(oscoreCtx, request);
	}

	/**
	 * Sets information in a source endpoint context for incoming responses.
	 *
	 * @param oscoreCtx the OSCORE context used for this message
	 * @param response the response to set the endpoint context for
	 */
	public static void receivingResponse(OSCoreCtx oscoreCtx, Response response) {
		setInfoIncoming(oscoreCtx, response);
	}

	/**
	 * Adds strings with information about the OSCORE context used to this
	 * source endpoint context for incoming messages.
	 *
	 * @param oscoreCtx the OSCORE context used for this message
	 * @param message the message to set information in the source endpoint
	 *            context for
	 */
	private static void setInfoIncoming(OSCoreCtx oscoreCtx, Message message) {

		// Create new MapBasedEndpointContext for source endpoint context with
		// string values for OSCORE added
		EndpointContext newEndpointContext = setInfo(oscoreCtx, message.getSourceContext());
		message.setSourceContext(newEndpointContext);
	}

	/**
	 * Adds strings with information about the OSCORE context used to this
	 * endpoint context (creating a new one).
	 *
	 * @param oscoreCtx the OSCORE context used
	 * @param endpointContext the original endpoint context to set information
	 *            based on
	 *
	 * @return the new endpoint context
	 */
	private static MapBasedEndpointContext setInfo(OSCoreCtx oscoreCtx, EndpointContext endpointContext) {

		// If endpoint context is not set, keep it unset
		if (endpointContext == null) {
			return null;
		}

		// Create new MapBasedEndpointContext for this endpoint context with
		// string values for OSCORE added
		List<String> attributes = new ArrayList<String>();
		add(attributes, OSCORE_SENDER_ID, oscoreCtx.getSenderIdString());
		add(attributes, OSCORE_RECIPIENT_ID, oscoreCtx.getRecipientIdString());
		add(attributes, OSCORE_CONTEXT_ID, oscoreCtx.getContextIdString());
		add(attributes, OSCORE_URI, oscoreCtx.getUri());
		MapBasedEndpointContext newEndpointContext = MapBasedEndpointContext.addEntries(endpointContext,
				attributes.toArray(new String[attributes.size()]));

		return newEndpointContext;
	}

	/**
	 * Add values and keys to a list if the value provided is not null.
	 *
	 * @param attributes the list to add values and keys to
	 * @param key the key to add
	 * @param value the value to add
	 */
	private static void add(List<String> attributes, String key, String value) {
		if (value != null) {
			attributes.add(key);
			attributes.add(value);
		}
	}
}
