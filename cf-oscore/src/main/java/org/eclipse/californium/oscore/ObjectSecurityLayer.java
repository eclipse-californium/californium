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
 *    Tobias Andersson (RISE SICS)
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.stack.AbstractLayer;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.ContextRederivation.PHASE;

/**
 * 
 * Applies OSCORE mechanics at stack layer.
 *
 */
public class ObjectSecurityLayer extends AbstractLayer {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(ObjectSecurityLayer.class.getName());

	private final OSCoreCtxDB ctxDb;

	public ObjectSecurityLayer(OSCoreCtxDB ctxDb) {
		if (ctxDb == null) {
			throw new NullPointerException("OSCoreCtxDB must be provided!");
		}
		this.ctxDb = ctxDb;
	}

	/**
	 * Encrypt an outgoing request using the OSCore context.
	 * 
	 * @param message the message
	 * @param ctxDb the context database used
	 * 
	 * @return the encrypted message
	 * 
	 * @throws OSException error while encrypting request
	 */
	public static Request prepareSend(OSCoreCtxDB ctxDb, Request message) throws OSException {
		return RequestEncryptor.encrypt(ctxDb, message);
	}

	/**
	 * Encrypt an outgoing response using the OSCore context.
	 * 
	 * @param message the message
	 * @param ctx the OSCore context
	 * @param newPartialIV boolean to indicate whether to use a new partial IV or not
	 * 
	 * @return the encrypted message
	 * 
	 * @throws OSException error while encrypting response
	 */
	public static Response prepareSend(OSCoreCtxDB ctxDb, Response message, OSCoreCtx ctx, final boolean newPartialIV) throws OSException {
		return ResponseEncryptor.encrypt(ctxDb, message, ctx, newPartialIV);
	}

	/**
	 * Decrypt an incoming request using the right OSCore context
	 *
	 * @param ctxDb the context database used
	 * @param request the incoming request
	 * 
	 * @return the decrypted and verified request
	 * 
	 * @throws CoapOSException error while decrypting request
	 */
	public static Request prepareReceive(OSCoreCtxDB ctxDb, Request request) throws CoapOSException {
		return RequestDecryptor.decrypt(ctxDb, request);
	}

	/**
	 * Decrypt an incoming response using the right OSCore context
	 *
	 * @param ctxDb the context database used
	 * @param response the incoming request
	 * @return the decrypted and verified response
	 * 
	 * @throws OSException error while decrypting response
	 */
	public static Response prepareReceive(OSCoreCtxDB ctxDb, Response response) throws OSException {
		return ResponseDecryptor.decrypt(ctxDb, response);
	}

	@Override
	public void sendRequest(Exchange exchange, Request request) {
		Request req = request;
		if (shouldProtectRequest(request)) {
			try {
				String uri = request.getURI();

				if (uri == null) {
					LOGGER.error(ErrorDescriptions.URI_NULL);
					throw new OSException(ErrorDescriptions.URI_NULL);
				}

				OSCoreCtx ctx = ctxDb.getContext(uri);
				if (ctx == null) {
					LOGGER.error(ErrorDescriptions.CTX_NULL);
					throw new OSException(ErrorDescriptions.CTX_NULL);
				}

				// Initiate context re-derivation procedure if flag is set
				if (ctx.getContextRederivationPhase() == PHASE.CLIENT_INITIATE) {
					throw new IllegalStateException("must be handled in ObjectSecurityContextLayer!");
				}

				/*
				 * Sets an operator on the exchange. This operator will in
				 * turn set information about the OSCORE context used in the
				 * endpoint context that will be created after the request is sent.
				 */
				OSCoreEndpointContextInfo.sendingRequest(ctx, exchange);

				exchange.setCryptographicContextID(ctx.getRecipientId());
				final int seqByToken = ctx.getSenderSeq();

				final Request preparedRequest = prepareSend(ctxDb, request);
				final OSCoreCtx finalCtx = ctxDb.getContext(uri);

				preparedRequest.addMessageObserver(new MessageObserverAdapter() {

					@Override
					public void onReadyToSend() {
						Token token = preparedRequest.getToken();
						ctxDb.addContext(token, finalCtx);
						ctxDb.addSeqByToken(token, seqByToken);
					}
				});

				req = preparedRequest;

			} catch (OSException e) {
				LOGGER.error("Error sending request: " + e.getMessage());
				return;
			} catch (IllegalArgumentException e) {
				LOGGER.error("Unable to send request because of illegal argument: " + e.getMessage());
				return;
			}
		}
		LOGGER.info("Request: " + exchange.getRequest().toString());
		super.sendRequest(exchange, req);
	}

	@Override
	public void sendResponse(Exchange exchange, Response response) {
		/* If the request contained the Observe option always add a partial IV to the response.
		 * A partial IV will also be added if the responsesIncludePartialIV flag is set in the context. */
		boolean addPartialIV;
		
		if (shouldProtectResponse(exchange)) {
			try {
				OSCoreCtx ctx = ctxDb.getContext(exchange.getCryptographicContextID());
				addPartialIV = ctx.getResponsesIncludePartialIV() || exchange.getRequest().getOptions().hasObserve();
				
				response = prepareSend(ctxDb, response, ctx, addPartialIV);
				exchange.setResponse(response);
			} catch (OSException e) {
				LOGGER.error("Error sending response: " + e.getMessage());
				return;
			}
		}
		super.sendResponse(exchange, response);
	}

	@Override
	public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
		super.sendEmptyMessage(exchange, message);
	}

	@Override
	public void receiveRequest(Exchange exchange, Request request) {
		if (isProtected(request)) {
			byte[] rid = null;
			try {
				request = prepareReceive(ctxDb, request);
				rid = request.getOptions().getOscore();
				request.getOptions().setOscore(Bytes.EMPTY);
				exchange.setRequest(request);
			} catch (CoapOSException e) {
				LOGGER.error("Error while receiving OSCore request: " + e.getMessage());
				Response error;
				error = CoapOSExceptionHandler.manageError(e, request);
				if (error != null) {
					super.sendResponse(exchange, error);
				}
				return;
			}
			exchange.setCryptographicContextID(rid);
		}
		super.receiveRequest(exchange, request);
	}

	//Always accepts unprotected responses, which is needed for reception of error messages
	@Override
	public void receiveResponse(Exchange exchange, Response response) {
		Request request = exchange.getCurrentRequest();
		if (request == null) {
			LOGGER.error("No request tied to this response");
			return;
		}
		try {
			//Printing of status information.
			//Warns when expecting OSCORE response but unprotected response is received
			if (!isProtected(response) && responseShouldBeProtected(exchange, response)) {
				LOGGER.warn("Incoming response is NOT OSCORE protected!");
			} else if (isProtected(response)) {
				LOGGER.info("Incoming response is OSCORE protected");
			}

			//If response is protected with OSCORE parse it first with prepareReceive
			if (isProtected(response)) {
				response = prepareReceive(ctxDb, response);
			}
		} catch (OSException e) {
			LOGGER.error("Error while receiving OSCore response: " + e.getMessage());
			EmptyMessage error = CoapOSExceptionHandler.manageError(e, response);
			if (error != null) {
				sendEmptyMessage(exchange, error);
			}
			return;
		}
		
		//Remove token if this is a response to a Observe cancellation request
		if (exchange.getRequest().isObserveCancel()) {
			ctxDb.removeToken(response.getToken());
		}
		
		super.receiveResponse(exchange, response);
	}

	@Override
	public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
		super.receiveEmptyMessage(exchange, message);
	}

	private static boolean shouldProtectResponse(Exchange exchange) {
		return exchange.getCryptographicContextID() != null;
	}

	//Method that checks if a response is expected to be protected with OSCORE
	private boolean responseShouldBeProtected(Exchange exchange, Response response) throws OSException {
		Request request = exchange.getCurrentRequest();
		OptionSet options = request.getOptions();
		if (exchange.getCryptographicContextID() == null) {
			if (response.getOptions().hasObserve() && request.getOptions().hasObserve()) {

				// Since the exchange object has been re-created the
				// cryptographic id doesn't exist
				if (options.hasOscore()) {
					String uri = request.getURI();
					try {
						OSCoreCtx ctx = ctxDb.getContext(uri);
						exchange.setCryptographicContextID(ctx.getRecipientId());
					} catch (OSException e) {
						LOGGER.error("Error when re-creating exchange at OSCORE level");
						throw new OSException("Error when re-creating exchange at OSCORE level");
					}
				}
			}
		}
		return exchange.getCryptographicContextID() != null;
	}

	private static boolean shouldProtectRequest(Request request) {
		OptionSet options = request.getOptions();
		return options.hasOption(OptionNumberRegistry.OSCORE);

	}

	private static boolean isProtected(Message message) {
		return message.getOptions().getOscore() != null;
	}
}
