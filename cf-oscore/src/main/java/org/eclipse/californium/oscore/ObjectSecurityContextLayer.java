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
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
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
	public void sendRequest(final Exchange exchange, final Request request) {
		if (shouldProtectRequest(request)) {
			try {
				final String uri = request.getURI();

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
					startRederivation.setDestinationContext(request.getDestinationContext());
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
									LOGGER.info("Original Request: " + exchange.getRequest().toString());
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
					LOGGER.trace("Auxiliary Request: " + exchange.getRequest().toString());
					final Exchange newExchange = new Exchange(startRederivation, Origin.LOCAL, executor);
					newExchange.execute(new Runnable() {

						@Override
						public void run() {
							ObjectSecurityContextLayer.super.sendRequest(newExchange, startRederivation);
						}
					});
					return;
				}

			} catch (OSException e) {
				LOGGER.error("Error sending request: " + e.getMessage());
				return;
			} catch (IllegalArgumentException e) {
				LOGGER.error("Unable to send request because of illegal argument: " + e.getMessage());
				return;
			}
		}
		LOGGER.trace("Request: " + exchange.getRequest().toString());
		super.sendRequest(exchange, request);
	}

	private static boolean shouldProtectRequest(Request request) {
		OptionSet options = request.getOptions();
		return options.hasOption(OptionNumberRegistry.OSCORE);
	}
}
