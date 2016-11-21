/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange.KeyToken;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.observe.NotificationListener;
import org.eclipse.californium.core.observe.Observation;
import org.eclipse.californium.core.observe.ObservationStore;
import org.eclipse.californium.elements.CorrelationContext;

/**
 * A base class for implementing Matchers that provides support for using a
 * {@code MessageExchangeStore}.
 */
public abstract class BaseMatcher implements Matcher {

	private static final Logger LOG = Logger.getLogger(BaseMatcher.class.getName());
	protected final NetworkConfig config;
	protected boolean running = false;
	protected MessageExchangeStore exchangeStore;
	protected ObservationStore observationStore;
	private NotificationListener notificationListener;

	/**
	 * Creates a new matcher based on configuration values.
	 * 
	 * @param config the configuration to use.
	 * @param notificationListener the callback to invoke for notifications
	 *            received from peers.
	 * @param observationStore the object to use for keeping track of
	 *            observations created by the endpoint this matcher is part of.
	 * @throws NullPointerException if the configuration, notification listener,
	 *             or the observation store is {@code null}.
	 */
	public BaseMatcher(final NetworkConfig config, final NotificationListener notificationListener,
			final ObservationStore observationStore) {
		if (config == null) {
			throw new NullPointerException("Config must not be null");
		} else if (notificationListener == null) {
			throw new NullPointerException("NotificationListener must not be null");
		} else if (observationStore == null) {
			throw new NullPointerException("ObservationStore must not be null");
		} else {
			this.config = config;
			this.notificationListener = notificationListener;
			this.observationStore = observationStore;
		}
	}

	@Override
	public synchronized final void setMessageExchangeStore(final MessageExchangeStore store) {
		if (running) {
			throw new IllegalStateException("MessageExchangeStore can only be set on stopped Matcher");
		} else if (store == null) {
			throw new NullPointerException("Message exchange store must not be null");
		} else {
			this.exchangeStore = store;
		}
	}

	protected final void assertMessageExchangeStoreIsSet() {
		if (exchangeStore == null) {
			LOG.log(Level.CONFIG, "no MessageExchangeStore set, using default {0}",
					InMemoryMessageExchangeStore.class.getName());
			exchangeStore = new InMemoryMessageExchangeStore(config);
		}
	}

	@Override
	public synchronized void start() {
		if (!running) {
			assertMessageExchangeStoreIsSet();
			exchangeStore.start();
			running = true;
		}
	}

	@Override
	public synchronized void stop() {
		if (running) {
			exchangeStore.stop();
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

		// We ignore blockwise request, except when this is an early negociation
		// (num and M is set to 0)
		if (!request.getOptions().hasBlock2() || request.getOptions().getBlock2().getNum() == 0
				&& !request.getOptions().getBlock2().isM()) {
			// add request to the store
			final KeyToken idByToken = KeyToken.fromOutboundMessage(request);
			LOG.log(Level.FINER, "registering observe request {0}", request);
			observationStore.add(new Observation(request, null));
			// remove it if the request is cancelled, rejected or timedout
			request.addMessageObserver(new MessageObserverAdapter() {

				@Override
				public void onCancel() {
					observationStore.remove(request.getToken());
					exchangeStore.releaseToken(idByToken);
				}

				@Override
				public void onReject() {
					observationStore.remove(request.getToken());
					exchangeStore.releaseToken(idByToken);
				}

				@Override
				public void onTimeout() {
					observationStore.remove(request.getToken());
					exchangeStore.releaseToken(idByToken);
				}
			});
		}
	}

	/**
	 * Special matching for notify reponses. Check, is a observe is stored in
	 * {@link #observationStore} and if found, recreate a exchange.
	 * 
	 * @param exchangeObserver exchange observer for the new exchange
	 * @param response notify response
	 * @param responseContext correlation context of response
	 * @return exchange, if a new one is create of the stored observe
	 *         informations, null, otherwise.
	 */
	protected final Exchange matchNotifyResponse(final ExchangeObserver exchangeObserver, final Response response,
			final CorrelationContext responseContext) {

		final Exchange.KeyToken idByToken = Exchange.KeyToken.fromInboundMessage(response);
		Exchange exchange = null;

		final Observation obs = observationStore.get(response.getToken());
		if (obs != null) {
			// there is an observation for the token from the response
			// re-create a corresponding Exchange object for it so
			// that the "upper" layers can correctly process the notification
			// response
			final Request request = obs.getRequest();
			request.setDestination(response.getSource());
			request.setDestinationPort(response.getSourcePort());
			exchange = new Exchange(request, Origin.LOCAL, obs.getContext());
			exchange.setRequest(request);
			exchange.setObserver(exchangeObserver);
			LOG.log(Level.FINER, "re-created exchange from original observe request: {0}", request);
			request.addMessageObserver(new MessageObserverAdapter() {

				@Override
				public void onTimeout() {
					observationStore.remove(request.getToken());
					exchangeStore.releaseToken(idByToken);
				}

				@Override
				public void onResponse(Response response) {
					// check whether the client has established the observe
					// requested
					if (!response.getOptions().hasObserve()) {
						// Observe response received with no observe option
						// set. It could be that the Client was not able to
						// establish the observe. So remove the observe
						// relation from observation store, which was stored
						// earlier when the request was sent.
						LOG.log(Level.FINE,
								"Response to observe request with token {0} does not contain observe option, removing request from observation store",
								idByToken);
						observationStore.remove(request.getToken());
						exchangeStore.releaseToken(idByToken);
					} else {
						notificationListener.onNotification(request, response);
					}
				}

				@Override
				public void onReject() {
					observationStore.remove(request.getToken());
					exchangeStore.releaseToken(idByToken);
				}

				@Override
				public void onCancel() {
					observationStore.remove(request.getToken());
					exchangeStore.releaseToken(idByToken);

				}
			});
		}

		return exchange;
	}

	/**
	 * Cancels all pending blockwise requests that have been induced by a
	 * notification we have received indicating a blockwise transfer of the
	 * resource.
	 * 
	 * @param token the token of the observation.
	 */
	@Override
	public void cancelObserve(final byte[] token) {
		// we do not know the destination endpoint the requests have been sent
		// to therefore we need to find them by token only
		for (Exchange exchange : exchangeStore.findByToken(token)) {
			exchange.getRequest().cancel();
			KeyToken idByToken = KeyToken.fromOutboundMessage(exchange.getCurrentRequest());
			exchangeStore.releaseToken(idByToken);
		}
		observationStore.remove(token);
	}

}
