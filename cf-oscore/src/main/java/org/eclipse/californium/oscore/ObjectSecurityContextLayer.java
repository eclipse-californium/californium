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
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.stack.AbstractLayer;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.ContextRederivation.PHASE;

/**
 * 
 * Applies OSCORE mechanics at stack layer.
 * 
 * Handles functionality for context re-derivation and outer block-wise.
 * https://tools.ietf.org/html/rfc8613#appendix-B.2
 * https://tools.ietf.org/html/rfc8613#section-4.1.3.4.2
 *
 */
public class ObjectSecurityContextLayer extends AbstractLayer {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(ObjectSecurityContextLayer.class);

	private final OSCoreCtxDB ctxDb;

	public ObjectSecurityContextLayer(OSCoreCtxDB ctxDb) {
		if (ctxDb == null) {
			throw new NullPointerException("OSCoreCtxDB must be provided!");
		}
		this.ctxDb = ctxDb;
	}

	@Override
	public void receiveRequest(Exchange exchange, Request request) {

		// Handle incoming OSCORE requests that have been re-assembled by the
		// block-wise layer (for outer block-wise). If an incoming request has
		// already been processed by OSCORE the option will be empty. If not it
		// is a re-assembled request to be processed here.
		boolean outerBlockwise = request.getOptions().hasOscore() && request.getOptions().getOscore().length != 0
				&& exchange.getCurrentRequest() != null && exchange.getCurrentRequest().getOptions().hasBlock1();
		if (isProtected(request) && outerBlockwise) {

			LOGGER.debug("Incoming OSCORE request uses outer block-wise");

			OSCoreCtx ctx = null;
			try {
				// Retrieve the OSCORE context for this RID and ID Context
				OscoreOptionDecoder optionDecoder = new OscoreOptionDecoder(request.getOptions().getOscore());
				byte[] rid = optionDecoder.getKid();
				byte[] IDContext = optionDecoder.getIdContext();

				ctx = ctxDb.getContext(rid, IDContext);
			} catch (CoapOSException e) {
				LOGGER.error("Error while receiving OSCore request: {}", e.getMessage());
				Response error;
				error = CoapOSExceptionHandler.manageError(e, request);
				if (error != null) {
					super.sendResponse(exchange, error);
				}
				return;
			}

			byte[] requestOscoreOption;
			try {
				request = RequestDecryptor.decrypt(ctxDb, request, ctx);
				requestOscoreOption = request.getOptions().getOscore();
				request.getOptions().setOscore(Bytes.EMPTY);
				exchange.setRequest(request);
			} catch (CoapOSException e) {
				LOGGER.error("Error while receiving OSCore request: {}", e.getMessage());
				Response error;
				error = CoapOSExceptionHandler.manageError(e, request);
				if (error != null) {
					super.sendResponse(exchange, error);
				}
				return;
			}
			exchange.setCryptographicContextID(requestOscoreOption);
		}
		super.receiveRequest(exchange, request);
	}

	@Override
	public void sendRequest(final Exchange exchange, final Request request) {
		if (shouldProtectRequest(request)) {
			try {
				final String uri;
				if (request.getOptions().hasProxyUri()) {
					uri = request.getOptions().getProxyUri();
				} else {
					uri = request.getURI();
				}

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
					ContextRederivation.setLostContext(ctxDb, uri);
					// send dummy request before to rederive the new context
					// and then send the original request using this new context
					final Request startRederivation = Request.newGet();
					startRederivation.setScheme(request.getScheme());
					startRederivation.setURI((request.getURI()));
					startRederivation.getOptions().setOscore(Bytes.EMPTY);
					startRederivation.getOptions().setUriPath("/rederivation/blackhole");
					startRederivation.addMessageObserver(new MessageObserverAdapter() {
						@Override
						public void onResponse(final Response response) {
							try {
								OSCoreCtx ctx = ctxDb.getContext(uri);
								if (ctx == null) {
									LOGGER.error(ErrorDescriptions.CTX_NULL);
								} else if (ctx.getContextRederivationPhase() != PHASE.CLIENT_PHASE_2) {
									LOGGER.error("Expected phase 2, but is {}", ctx.getContextRederivationPhase());
								}
							} catch (OSException e) {
							}

							// send original request, if the start rederivation receives a response
							exchange.execute(new Runnable() {

								@Override
								public void run() {
									LOGGER.debug("Original Request: {}", exchange.getRequest());
									ObjectSecurityContextLayer.super.sendRequest(exchange, request);
								}
							});
						}

						@Override
						public void onReject() {
							// forward rejection to original request
							request.setRejected(true);
						}

						@Override
						public void onCancel() {
							// forward cancel to original request
							request.setCanceled(true);
						}

						@Override
						public void onTimeout() {
							// forward timeout to original request
							request.setTimedOut(true);
						}

						@Override
						public void onConnecting() {
							// forward on connect to original request
							request.onConnecting();
						}

						@Override
						public void onDtlsRetransmission(int flight) {
							// forward dtls handshake retransmission to original request
							request.onDtlsRetransmission(flight);
						}

						@Override
						// forward send error to original request
						public void onSendError(Throwable error) {
							request.setSendError(error);
						}

					});
					// send start rederivation request
					LOGGER.debug("Auxiliary Request: {}", exchange.getRequest());
					final Exchange newExchange = new Exchange(startRederivation, exchange.getPeersIdentity(), Origin.LOCAL, executor);
					newExchange.execute(new Runnable() {

						@Override
						public void run() {
							ObjectSecurityContextLayer.super.sendRequest(newExchange, startRederivation);
						}
					});
					return;
				}

			} catch (OSException e) {
				LOGGER.error("Error sending request: {}", e.getMessage());
				return;
			} catch (IllegalArgumentException e) {
				LOGGER.error("Unable to send request because of illegal argument: {}", e.getMessage());
				return;
			}
		}
		LOGGER.trace("Request: {}", exchange.getRequest());
		super.sendRequest(exchange, request);
	}

	@Override
	public void receiveResponse(Exchange exchange, Response response) {

		// Handle incoming OSCORE responses that have been re-assembled by the
		// block-wise layer (for outer block-wise). If a response was not
		// processed by OSCORE in the ObjectSecurityLayer it will happen here.
		Response rawResponse =  exchange.getCurrentResponse();
		boolean outerBlockwise = rawResponse != null && rawResponse.getOptions().hasBlock2()
				&& ctxDb.getContextByToken(rawResponse.getToken()) != null;
		if (outerBlockwise) {

			LOGGER.debug("Incoming OSCORE response uses outer block-wise");

			Request request = exchange.getCurrentRequest();
			if (request == null) {
				LOGGER.error("No request tied to this response");
				return;
			}
			try {
				// If response is protected with OSCORE parse it first with
				// prepareReceive
				if (isProtected(response)) {
					// Parse the OSCORE option from the corresponding request
					OscoreOptionDecoder optionDecoder = new OscoreOptionDecoder(exchange.getCryptographicContextID());
					int requestSequenceNumber = optionDecoder.getSequenceNumber();
					
					response = ObjectSecurityLayer.prepareReceive(ctxDb, response,
							requestSequenceNumber);
				}
			} catch (OSException e) {
				LOGGER.error("Error while receiving OSCore response: {}", e.getMessage());
				EmptyMessage error = CoapOSExceptionHandler.manageError(e, response);
				if (error != null) {
					sendEmptyMessage(exchange, error);
				}
				return;
			}

			// Remove token if this is a response to a Observe cancellation
			// request
			if (exchange.getRequest().isObserveCancel()) {
				ctxDb.removeToken(response.getToken());
			}
		}

		super.receiveResponse(exchange, response);
	}

	private static boolean shouldProtectRequest(Request request) {
		OptionSet options = request.getOptions();
		return options.hasOscore();
	}

	private static boolean isProtected(Message message) {
		OptionSet options = message.getOptions();
		return options.hasOscore();
	}
}
