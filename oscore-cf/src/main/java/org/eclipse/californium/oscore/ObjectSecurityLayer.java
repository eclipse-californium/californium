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
 *    Tobias Andersson (RISE SICS)
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

	private static final byte[] EMPTY = new byte[0];

	/**
	 * Encrypt an outgoing request using the OSCore context.
	 * 
	 * @param message the message
	 * @param ctx the OSCore context
	 * 
	 * @return the encrypted message
	 * 
	 * @throws OSException error while encrypting request
	 */
	public static Request prepareSend(Request message, OSCoreCtx ctx) throws OSException {
		return RequestEncryptor.encrypt(message, ctx);
	}

	/**
	 * Encrypt an outgoing response using the OSCore context.
	 * 
	 * @param message the message
	 * @param ctx the OSCore context
	 * 
	 * @return the encrypted message
	 * 
	 * @throws OSException error while encrypting response
	 */
	public static Response prepareSend(Response message, OSCoreCtx ctx, final boolean newPartialIV) throws OSException {
		return ResponseEncryptor.encrypt(message, ctx, newPartialIV);
	}

	/**
	 * Decrypt an incoming request using the right OSCore context
	 * 
	 * @param request the incoming request
	 * @param db the OSCore context database
	 * 
	 * @return the cid of the OSCore context used for this request
	 * 
	 * @throws OSException error while decrypting request
	 */
	public static Request prepareReceive(Request request) throws CoapOSException {
		return RequestDecryptor.decrypt(request);
	}

	/**
	 * Decrypt an incoming response using the right OSCore context
	 * 
	 * @param response the incoming request
	 * @param db the OSCore context database
	 * @return the decrypted and verified response
	 * 
	 * @throws OSException error while decrypting response
	 */
	public static Response prepareReceive(Response response) throws OSException {
		return ResponseDecryptor.decrypt(response);
	}

	@Override
	public void sendRequest(Exchange exchange, Request request) {
		Request req = request;
		if (shouldProtectRequest(request)) {
			try {
				String uri = request.getURI();
				final OSCoreCtxDB db = HashMapCtxDB.getInstance();

				if (uri == null) {
					LOGGER.error(Error.URI_NULL);
					throw new OSException(Error.URI_NULL);
				}
				if (db == null) {
					LOGGER.error(Error.DB_NULL);
					throw new OSException(Error.DB_NULL);
				}

				final OSCoreCtx ctx = db.getContext(uri);
				if (ctx == null) {
					LOGGER.error(Error.CTX_NULL);
					throw new OSException(Error.CTX_NULL);
				}

				exchange.setCryptographicContextID(ctx.getRecipientId());
				final int seqByToken = ctx.getSenderSeq();

				final Request preparedRequest = prepareSend(request, ctx);
				preparedRequest.addMessageObserver(new MessageObserverAdapter() {

					@Override
					public void onReadyToSend() {
						Token token = preparedRequest.getToken();
						db.addContext(token, ctx);
						db.addSeqByToken(token, seqByToken);
					}
				});

				req = preparedRequest;

				if (req.getToken() != null) {
					db.addContext(request.getToken(), ctx);
					db.addSeqByToken(request.getToken(), seqByToken);
				}
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
		if (shouldProtectResponse(exchange)) {
			try {
				HashMapCtxDB db = HashMapCtxDB.getInstance();
				OSCoreCtx ctx = db.getContext(exchange.getCryptographicContextID());
				response = prepareSend(response, ctx, false);
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
				request = prepareReceive(request);
				rid = request.getOptions().getOscore();
				request.getOptions().setOscore(EMPTY);
				exchange.setRequest(request);
			} catch (CoapOSException e) {
				LOGGER.error("Error while receiving OSCore request: " + e.getMessage());
				Response error;
				try {
					error = CoapOSExceptionHandler.manageError(e, request);
					if (error != null) {
						super.sendResponse(exchange, error);
					}
					return;
				} catch (OSException e1) {
					e1.printStackTrace();
				}
			}
			exchange.setCryptographicContextID(rid);
		}
		super.receiveRequest(exchange, request);
	}

	@Override
	public void receiveResponse(Exchange exchange, Response response) {
		Request request = exchange.getCurrentRequest();
		if (request == null) {
			LOGGER.error("No request tied to this response");
			return;
		}
		try {
			if (responseShouldBeProtected(exchange, response)) {
				if (!isProtected(response)) {
					LOGGER.error("Unprotected OSCore response received" + " for OSCore request");
					LOGGER.error("Response: " + response.toString());
					return;
				}
				response = prepareReceive(response);

			}
		} catch (OSException e) {
			LOGGER.error("Error while receiving OSCore response: " + e.getMessage());
			EmptyMessage error = CoapOSExceptionHandler.manageError(e, response);
			if (error != null) {
				sendEmptyMessage(exchange, error);
			}
			return;
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

	private static boolean responseShouldBeProtected(Exchange exchange, Response response) throws OSException {
		Request request = exchange.getCurrentRequest();
		OptionSet options = request.getOptions();
		if (exchange.getCryptographicContextID() == null) {
			if (response.getOptions().hasObserve() && request.getOptions().hasObserve()) {

				// Since the exchange object has been re-created the
				// cryptographic id doesn't exist
				if (options.hasOscore()) {
					String uri = request.getURI();
					OSCoreCtxDB db = HashMapCtxDB.getInstance();
					OSCoreCtx ctx = null;
					try {
						ctx = db.getContext(uri);
					} catch (OSException e) {
						LOGGER.error("Error when re-creating exchange at OSCORE level");
						throw new OSException("Error when re-creating exchange at OSCORE level");
					}
					exchange.setCryptographicContextID(ctx.getRecipientId());
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
