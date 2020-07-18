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
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
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
	private static final Logger LOGGER = LoggerFactory.getLogger(ObjectSecurityLayer.class);

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
	 * @param ctxDb the OSCore context DB
	 * @param message the message
	 * @param ctx the OSCore context
	 * @param newPartialIV boolean to indicate whether to use a new partial IV or not
	 * @param outerBlockwise boolean to indicate whether the block-wise options
	 *            should be encrypted or not
	 * 
	 * @return the encrypted message
	 * 
	 * @throws OSException error while encrypting response
	 */
	public static Response prepareSend(OSCoreCtxDB ctxDb, Response message, OSCoreCtx ctx, final boolean newPartialIV,
			boolean outerBlockwise) throws OSException {
		return ResponseEncryptor.encrypt(ctxDb, message, ctx, newPartialIV, outerBlockwise);
	}

	/**
	 * Decrypt an incoming request using the right OSCore context
	 *
	 * @param ctxDb the context database used
	 * @param request the incoming request
	 * @param ctx the OSCore context
	 * 
	 * @return the decrypted and verified request
	 * 
	 * @throws CoapOSException error while decrypting request
	 */
	public static Request prepareReceive(OSCoreCtxDB ctxDb, Request request, OSCoreCtx ctx) throws CoapOSException {
		return RequestDecryptor.decrypt(ctxDb, request, ctx);
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
	public void sendRequest(final Exchange exchange, final Request request) {
		Request req = request;
		if (shouldProtectRequest(request)) {
			try {
				// Handle outgoing requests for more data from a responder that
				// is responding with outer block-wise. These requests should
				// not be processed with OSCORE.
				boolean outerBlockwise = request.getOptions().hasBlock2() && exchange.getCurrentResponse() != null
						&& ctxDb.getContextByToken(exchange.getCurrentResponse().getToken()) != null;
				if (outerBlockwise) {
					super.sendRequest(exchange, req);
					return;
				}

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

				if (outgoingExceedsMaxUnfragSize(preparedRequest, outerBlockwise, ctx.getMaxUnfragmentedSize())) {
					throw new IllegalStateException("outgoing request is exceeding the MAX_UNFRAGMENTED_SIZE!");
				}

				preparedRequest.addMessageObserver(0, new MessageObserverAdapter() {

					@Override
					public void onReadyToSend() {
						Token token = preparedRequest.getToken();

						// add at head of message observers to update
						// the token of the original request first,
						// before calling other message observers!
						if (request.getToken() == null) {
							request.setToken(token);
						}

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
		
		/*
		 * If the original request used outer block-wise options so should the
		 * response. (They are not encrypted but external unprotected options.)
		 */
		boolean outerBlockwise;

		if (shouldProtectResponse(exchange)) {
			// If the current block-request still has a non-empty OSCORE option it
			// means it was not unprotected by OSCORE as and individual request.
			// Rather it was not processed by OSCORE until after being re-assembled
			// by the block-wise layer. Thus the response should use outer block options.
			outerBlockwise = exchange.getCurrentRequest().getOptions().hasOscore()
					&& exchange.getCurrentRequest().getOptions().getOscore().length != 0;

			try {
				OSCoreCtx ctx = ctxDb.getContextByToken(exchange.getCurrentRequest().getToken());
				addPartialIV = ctx.getResponsesIncludePartialIV() || exchange.getRequest().getOptions().hasObserve();

				Response preparedResponse = prepareSend(ctxDb, response, ctx, addPartialIV, outerBlockwise);

				if (outgoingExceedsMaxUnfragSize(preparedResponse, outerBlockwise, ctx.getMaxUnfragmentedSize())) {
					super.sendResponse(exchange,
							Response.createResponse(exchange.getCurrentRequest(), ResponseCode.INTERNAL_SERVER_ERROR));
					throw new IllegalStateException("outgoing response is exceeding the MAX_UNFRAGMENTED_SIZE!");
				}

				response = preparedResponse;
				exchange.setResponse(response);
			} catch (OSException e) {
				LOGGER.error("Error sending response: " + e.getMessage());
				return;
			}
		}

		// Remove token after response is transmitted, unless ongoing Observe.
		// Takes token from corresponding request
		if (response.getOptions().hasObserve() == false || exchange.getRequest().isObserveCancel()) {
			ctxDb.removeToken(exchange.getCurrentRequest().getToken());
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

			// Retrieve the OSCORE context associated with this RID and ID Context
			byte[] rid = OptionJuggle.getRid(request.getOptions().getOscore());
			byte[] IDContext = OptionJuggle.getIDContext(request.getOptions().getOscore());

			OSCoreCtx ctx = null;
			try {
				ctx = ctxDb.getContext(rid, IDContext);
			} catch (CoapOSException e) {
				LOGGER.error("Error while receiving OSCore request: " + e.getMessage());
				Response error;
				error = CoapOSExceptionHandler.manageError(e, request);
				if (error != null) {
					super.sendResponse(exchange, error);
				}
				return;
			}

			// For OSCORE-protected requests with the outer block1-option let
			// them pass through to be re-assembled by the block-wise layer
			if (request.getOptions().hasBlock1()) {

				if (request.getMaxResourceBodySize() == 0) {
					int maxPayloadSize = getIncomingMaxUnfragSize(request, ctx);
					request.setMaxResourceBodySize(maxPayloadSize);
				}

				super.receiveRequest(exchange, request);
				return;
			}

			try {
				request = prepareReceive(ctxDb, request, ctx);
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

			// For OSCORE-protected response with the outer block2-option let
			// them pass through to be re-assembled by the block-wise layer
			if (response.getOptions().hasBlock2()) {

				if (response.getMaxResourceBodySize() == 0) {
					int maxPayloadSize = getIncomingMaxUnfragSize(response, ctxDb);
					response.setMaxResourceBodySize(maxPayloadSize);
				}

				super.receiveResponse(exchange, response);
				return;
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
		
		// Remove token if this is an incoming response to an Observe
		// cancellation request
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

	/**
	 * Check if a message being sent exceeds the MAX_UNFRAGMENTED_SIZE and is
	 * not using inner block-wise. If so it should not be sent.
	 * 
	 * @param message the CoAP message
	 * @param maxUnfragmentedSize the MAX_UNFRAGMENTED_SIZE value
	 * 
	 * @return if the message exceeds the MAX_UNFRAGMENTED_SIZE
	 */
	private boolean outgoingExceedsMaxUnfragSize(Message message, boolean outerBlockwise,
			int maxUnfragmentedSize) {

		boolean usesInnerBlockwise = (message.getOptions().hasBlock1() == true
				|| message.getOptions().hasBlock2() == true) && outerBlockwise == false;

		if (message.getPayloadSize() > maxUnfragmentedSize && usesInnerBlockwise == false) {
			return true;
		} else {
			return false;
		}

	}

	/**
	 * Gets the MAX_UNFRAGMENTED_SIZE size for an incoming block-wise transfer.
	 * If outer block-wise is used this value will be set using
	 * setMaxResourceBodySize on the incoming request or response and enforced
	 * in the BlockwiseLayer. Reception of messages where the cumulative payload
	 * size exceeds this value will be aborted.
	 * 
	 * @param message the CoAP message
	 * @param ctx the context used
	 * 
	 * @return the MAX_UNFRAGMENTED_SIZE value to be used
	 */
	private int getIncomingMaxUnfragSize(Message message, OSCoreCtx ctx) {

		// No limit if no context is found. A null context will be handled later
		if (ctx == null) {
			return 0;
		} else {
			return ctx.getMaxUnfragmentedSize();
		}

	}

	/**
	 * Separate version of method for handling responses.
	 * 
	 * @param message the CoAP message
	 * @param ctxDb the context database used
	 * @return the MAX_UNFRAGMENTED_SIZE value to be used
	 */
	private int getIncomingMaxUnfragSize(Message message, OSCoreCtxDB ctxDb) {
		OSCoreCtx ctx = null;
		if (message instanceof Response) {
			ctx = ctxDb.getContextByToken(message.getToken());
		}

		return getIncomingMaxUnfragSize(message, ctx);
	}

}
