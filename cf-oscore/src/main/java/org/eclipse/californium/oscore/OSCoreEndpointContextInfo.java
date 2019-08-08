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
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.EndpointContextOperator;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;

/**
 * Class that handles setting information in an EndpointContext for OSCORE messages. 
 *
 * It provides functionality to set appropriate information about the OSCORE 
 * context used, as strings in the map inside an EndpointContext.
 *
 * When an application is receiving a message or sending a request
 * it can use the strings in the EndpointContext to retrieve information
 * about what OSCORE context was used for this messages.
 *
 * Information that can be retrieved is the URI associated to the OSCORE context,
 * the Sender ID, Recipient ID and Context ID of the OSCORE context.
 *
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
     * the exchange that sets the appropriate information in the endpoint context
     * that will be created after the request is sent.
     *
     * @param oscoreCtx the OSCORE context used for this message
     * @param exchange the exchange to later set the endpoint context for
     */
    public static void sendingRequest(OSCoreCtx oscoreCtx, Exchange exchange) {
        exchange.setEndpointContextPreOperator(new OSCoreEndpointContextOperator(oscoreCtx));
    }

    /**
     * Class that functions as an operator on the exchange. It will set information about
     * the OSCORE context used on the new endpoint context created after the request is sent.
     *
     * This new endpoint context is available using
     * MessageObserver.onContextEstablished(EndpointContext).
     *
     */
    private static class OSCoreEndpointContextOperator implements EndpointContextOperator {

        /**
         * OSCORE context to take information from to set in the endpoint context
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
         * Method that will be ran when setting the endpoint context for an exchange.
         * Should perform changes to the endpoint context to add the OSCORE-related strings.
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
     * Sets information in a destination endpoint context for outgoing responses.
     *
     * @param oscoreCtx the OSCORE context used for this message
     * @param response the response to set the endpoint context for
     */
    public static void sendingResponse(OSCoreCtx oscoreCtx, Response response) {
        setInfoOutgoing(oscoreCtx, response);
    }

    /**
     * Sets information in a destination endpoint context for incoming responses.
     *
     * @param oscoreCtx the OSCORE context used for this message
     * @param response the response to set the endpoint context for
     */
    public static void receivingResponse(OSCoreCtx oscoreCtx, Response response) {
        setInfoIncoming(oscoreCtx, response);
    }

    /**
     * Adds strings with information about the OSCORE context used to this
     * destination endpoint context for outgoing messages.
     *
     * @param oscoreCtx the OSCORE context used for this message
     * @param message the message to set information in the destination endpoint context for
     */
    private static void setInfoOutgoing(OSCoreCtx oscoreCtx, Message message) {

        //Create new MapBasedEndpointContext for destination endpoint context with string values for OSCORE added
        EndpointContext newEndpointContext = setInfo(oscoreCtx, message.getDestinationContext());
        message.setDestinationContext(newEndpointContext);
    }

    /**
     * Adds strings with information about the OSCORE context used to this
     * source endpoint context for incoming messages.
     *
     * @param oscoreCtx the OSCORE context used for this message
     * @param message the message to set information in the source endpoint context for
     */
    private static void setInfoIncoming(OSCoreCtx oscoreCtx, Message message) {

        //Create new MapBasedEndpointContext for source endpoint context with string values for OSCORE added
        EndpointContext newEndpointContext = setInfo(oscoreCtx, message.getSourceContext());
        message.setSourceContext(newEndpointContext);
    }

    /**
     * Adds strings with information about the OSCORE context used to this
     * endpoint context (creating a new one).
     *
     * @param oscoreCtx the OSCORE context used
     * @param endpointContext the original endpoint context to set information based on
     *
     * @return the new endpoint context
     */
    private static MapBasedEndpointContext setInfo(OSCoreCtx oscoreCtx, EndpointContext endpointContext) {

    	//If endpoint context is not set, keep it unset
    	if (endpointContext == null) {
    		return null;
    	}
    	
        //Create new MapBasedEndpointContext for this endpoint context with string values for OSCORE added
        MapBasedEndpointContext newEndpointContext = MapBasedEndpointContext.addEntries(
                endpointContext,
                OSCORE_SENDER_ID, oscoreCtx.getSenderIdString(),
                OSCORE_RECIPIENT_ID, oscoreCtx.getRecipientIdString(),
                OSCORE_CONTEXT_ID, oscoreCtx.getContextIdString(),
                OSCORE_URI, oscoreCtx.getUri());

        return newEndpointContext;
    }
}
