/*******************************************************************************
 * Copyright (c) 2016, 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove ExchangeObserver.
 *                                                    Notify exchanges are not 
 *                                                    stored within the matcher
 *                                                    and therefore don't require
 *                                                    a cleanup.
 *    Achim Kraus (Bosch Software Innovations GmbH) - make exchangeStore final
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix cancelObserve()
 *    Achim Kraus (Bosch Software Innovations GmbH) - use new introduced failed() 
 *                                                    instead of onReject() and
 *                                                    onTimeout().
 *    Achim Kraus (Bosch Software Innovations GmbH) - don't cleanup on cancel
 *                                                    for received notifies
 *    Achim Kraus (Bosch Software Innovations GmbH) - cleanup on cancel again :-).
 *                                                    complete exchange on 
 *                                                    cancelObserve.
 *    Achim Kraus (Bosch Software Innovations GmbH) - check for observe option
 *                                                    in response, before lookup
 *                                                    for observes
 *    Achim Kraus (Bosch Software Innovations GmbH) - check for observe option only
 *                                                    in success response, before
 *                                                    lookup for observes.
 *                                                    According RFC7641, 4.2, page 15, 
 *                                                    none success notify-responses
 *                                                    would terminate the observation
 *                                                    and therefore doesn't contain a
 *                                                    observe option.
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace parameter EndpointContext 
 *                                                    by EndpointContext of response.
 *    Achim Kraus (Bosch Software Innovations GmbH) - ignore timeout on blockwise notify
 *                                                    issue 451
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - forward error notifies
 *                                                    issue 465
 *    Achim Kraus (Bosch Software Innovations GmbH) - adjust to use Token
 *                                                    remove not longer required
 *                                                    releaseToken
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 *    Achim Kraus (Bosch Software Innovations GmbH) - add token generator 
 *                                                    retry-loop for observes
 *    Achim Kraus (Bosch Software Innovations GmbH) - don't remove observe 
 *                                                    on cancel of notify
 *    Achim Kraus (Bosch Software Innovations GmbH) - reduce multiple calls of
 *                                                    observation store remove.
 *                                                    Remove observation, if response
 *                                                    doesn't contain an observe option 
 *    Achim Kraus (Bosch Software Innovations GmbH) - move onContextEstablished
 *                                                    to MessageObserver.
 *                                                    Issue #487
 *    Achim Kraus (Bosch Software Innovations GmbH) - striped exchange execution
 ******************************************************************************/
package org.eclipse.californium.core.network;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

import org.eclipse.californium.core.coap.InternalMessageObserverAdapter;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.TokenGenerator.Scope;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.observe.NotificationListener;
import org.eclipse.californium.core.observe.Observation;
import org.eclipse.californium.core.observe.ObservationStore;
import org.eclipse.californium.elements.EndpointContext;

/**
 * A base class for implementing Matchers that provides support for using a
 * {@code MessageExchangeStore}.
 */
public abstract class BaseMatcher implements Matcher {

	private static final Logger LOG = LoggerFactory.getLogger(BaseMatcher.class);
	protected final NetworkConfig config;
	protected final ObservationStore observationStore;
	protected final MessageExchangeStore exchangeStore;
	protected final TokenGenerator tokenGenerator;
	protected final Executor executor;
	protected boolean running = false;
	private final NotificationListener notificationListener;

	/**
	 * Creates a new matcher based on configuration values.
	 * 
	 * @param config the configuration to use.
	 * @param notificationListener the callback to invoke for notifications
	 *            received from peers.
	 * @param tokenGenerator token generator to create tokens for observations
	 *            created by the endpoint this matcher is part of.
	 * @param observationStore the object to use for keeping track of
	 *            observations created by the endpoint this matcher is part of.
	 * @param exchangeStore the exchange store to use for keeping track of
	 *            message exchanges with endpoints.
	 * @param executor executor to be used for exchanges.
	 * @throws NullPointerException if one of the parameters is {@code null}.
	 */
	public BaseMatcher( NetworkConfig config,  NotificationListener notificationListener,
			 TokenGenerator tokenGenerator,  ObservationStore observationStore,
			 MessageExchangeStore exchangeStore, Executor executor) {
		if (config == null) {
			throw new NullPointerException("Config must not be null");
		} else if (notificationListener == null) {
			throw new NullPointerException("NotificationListener must not be null");
		} else if (tokenGenerator == null) {
			throw new NullPointerException("TokenGenerator must not be null");
		} else if (exchangeStore == null) {
			throw new NullPointerException("MessageExchangeStore must not be null");
		} else if (observationStore == null) {
			throw new NullPointerException("ObservationStore must not be null");
		} else {
			this.config = config;
			this.notificationListener = notificationListener;
			this.exchangeStore = exchangeStore;
			this.observationStore = observationStore;
			this.tokenGenerator = tokenGenerator;
			this.executor = executor;
		}
	}

	@Override
	public synchronized void start() {
		if (!running) {
			exchangeStore.start();
			observationStore.start();
			running = true;
		}
	}

	@Override
	public synchronized void stop() {
		if (running) {
			exchangeStore.stop();
			observationStore.stop();
			clear();
			running = false;
		}
	}

	/**
	 * This method does nothing.
	 * <p>
	 * Subclasses should override this method in order to clear any internal
	 * state.
	 */
	@Override
	public void clear() {
	}

	/**
	 * Register observe request.
	 * 
	 * Add observe request to the {@link #observationStore} and set a message
	 * observer.
	 * 
	 * @param request observe request.
	 */
	protected final void registerObserve(final Request request) {

		// Ignore follow-up blockwise request
		if (!request.getOptions().hasBlock2() || request.getOptions().getBlock2().getNum() == 0) {
			// add request to the store
			LOG.debug("registering observe request {}", request);
			Token token = request.getToken();
			if (token == null) {
				do {
					token = tokenGenerator.createToken(Scope.LONG_TERM);
					request.setToken(token);
				} while (observationStore.putIfAbsent(token, new Observation(request, null)) != null);
			} else {
				observationStore.put(token, new Observation(request, null));
			}
			// Add observer to remove observation, if the request is cancelled,
			// rejected, timed out, or send error is reported
			request.addMessageObserver(new ObservationObserverAdapter(token) {

				@Override
				public void onCancel() {
					remove();
				}

				@Override
				protected void failed() {
					remove();
				}

				@Override
				public void onContextEstablished(EndpointContext endpointContext) {
					observationStore.setContext(token, endpointContext);
				}
			});
		}
	}

	/**
	 * Special matching for notify responses. Check, is a observe is stored in
	 * {@link #observationStore} and if found, recreate a exchange.
	 * 
	 * @param response notify response
	 * @return exchange, if a new one is create of the stored observe
	 *         informations, null, otherwise.
	 */
	protected final Exchange matchNotifyResponse(final Response response) {

		Exchange exchange = null;
		if (!CoAP.ResponseCode.isSuccess(response.getCode()) || response.getOptions().hasObserve()) {
			Token token = response.getToken();
			Observation obs = observationStore.get(token);
			if (obs != null) {
				// there is an observation for the token from the response
				// re-create a corresponding Exchange object for it so
				// that the "upper" layers can correctly process the
				// notification response
				final Request request = obs.getRequest();
				exchange = new Exchange(request, Origin.LOCAL, executor, obs.getContext(), true);
				LOG.debug("re-created exchange from original observe request: {}", request);
				request.addMessageObserver(new ObservationObserverAdapter(token) {

					@Override
					public void onResponse(Response response) {
						try {
							notificationListener.onNotification(request, response);
						} finally {
							if (!response.isNotification()) {
								// Observe response received with no observe
								// option set. It could be that the Client was
								// not able to establish the observe. So remove
								// the observe relation from observation store,
								// which was stored earlier when the request was
								// sent.
								LOG.debug("observation with token {} removed, removing from observation store", token);
								remove();
							}
						}
					}
				});
			}
		}
		return exchange;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Cancels all pending blockwise requests that have been induced by a
	 * notification we have received indicating a blockwise transfer of the
	 * resource.
	 */
	@Override
	public void cancelObserve(Token token) {
		// Note: the initial observe exchanges is not longer stored with
		// the original token but a pending blockwise notifies may still
		// have a request with that token.
		boolean found = false;
		for (Exchange exchange : exchangeStore.findByToken(token)) {
			Request request = exchange.getRequest();
			if (request.isObserve()) {
				// cancel only observe requests,
				// not "token" related proactive cancel observe request!
				request.cancel();
				if (!exchange.isNotification()) {
					// Message.cancel() already released the token
					found = true;
				}
				exchange.executeComplete();
			}
		}
		if (!found) {
			// if a exchange was found,
			// the request.cancel() has already removed the observation
			observationStore.remove(token);
		}
	}

	/**
	 * Message observer removing observations. May be shared by multiple (block)
	 * request and will call {@link ObservationStore#remove(Token)} only once.
	 */
	private class ObservationObserverAdapter extends InternalMessageObserverAdapter {

		/**
		 * Flag to suppress multiple observation store remove calls.
		 */
		protected final AtomicBoolean removed = new AtomicBoolean();
		/**
		 * Token to remove.
		 */
		protected final Token token;

		/**
		 * Create observer.
		 * 
		 * @param token token to remove
		 */
		public ObservationObserverAdapter(Token token) {
			this.token = token;
		}

		@Override
		public void onResponse(Response response) {
			Observation observation = observationStore.get(token);
			if (observation != null) {
				if (response.isError() || !response.isNotification()) {
					LOG.debug("observation with token {} not established, removing from observation store", token);
					remove();
				}
			}
		}

		/**
		 * Remove token from observation store. Mostly called once.
		 */
		protected void remove() {
			if (removed.compareAndSet(false, true)) {
				observationStore.remove(token);
			}
		}
	}
}
