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
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove only provided Exchange
 *                                                    Observes and blockwise 
 *                                                    exchanges may be used 
 *                                                    longer, so that MID (observe)
 *                                                    or token (blockwise) may
 *                                                    be reused for an other
 *                                                    exchange.
 *    Achim Kraus (Bosch Software Innovations GmbH) - apply formatter
 *    Achim Kraus (Bosch Software Innovations GmbH) - cleanup synchronization
 *                                                    integrate clear() into stop()
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove setContext().
 *                                                    issue #311
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.net.InetSocketAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.Exchange.KeyMID;
import org.eclipse.californium.core.network.Exchange.KeyToken;
import org.eclipse.californium.core.network.Exchange.KeyUri;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.deduplication.Deduplicator;
import org.eclipse.californium.core.network.deduplication.DeduplicatorFactory;
import org.eclipse.californium.elements.util.DaemonThreadFactory;


/**
 * A {@code MessageExchangeStore} that manages all exchanges in local memory.
 *
 */
public class InMemoryMessageExchangeStore implements MessageExchangeStore {

	private static final Logger LOGGER = Logger.getLogger(InMemoryMessageExchangeStore.class.getName());
	private final ConcurrentMap<KeyMID, Exchange> exchangesByMID = new ConcurrentHashMap<>(); // for all
	private final ConcurrentMap<KeyToken, Exchange> exchangesByToken = new ConcurrentHashMap<>(); // for outgoing
	private final ConcurrentMap<KeyUri, Exchange> ongoingExchanges = new ConcurrentHashMap<>();

	private final NetworkConfig config;
	private final TokenProvider tokenProvider;
	private boolean running = false;
	private volatile Deduplicator deduplicator;
	private volatile MessageIdProvider messageIdProvider;
	private ScheduledFuture<?> statusLogger;
	private ScheduledExecutorService scheduler;

	/**
	 * Creates a new store for configuration values.
	 * 
	 * @param config the configuration to use.
	 * 
	 */
	public InMemoryMessageExchangeStore(final NetworkConfig config) {
		this(config, new InMemoryRandomTokenProvider(config));
		LOGGER.log(Level.CONFIG, "using default TokenProvider {0}", InMemoryRandomTokenProvider.class.getName());
	}

	/**
	 * Creates a new store for configuration values.
	 * 
	 * @param config the configuration to use.
	 * @param tokenProvider the TokenProvider which provides CoAP tokens that
	 *            are guaranteed to be not in use.
	 * 
	 */
	public InMemoryMessageExchangeStore(final NetworkConfig config, TokenProvider tokenProvider) {
		if (config == null) {
			throw new NullPointerException("Configuration must not be null");
		}
		if (tokenProvider == null) {
			throw new NullPointerException("TokenProvider must not be null");
		}
		this.tokenProvider = tokenProvider;
		this.config = config;
	}

	private void startStatusLogging() {

		final Level healthStatusLevel = Level.parse(config.getString(NetworkConfig.Keys.HEALTH_STATUS_PRINT_LEVEL, Level.FINEST.getName()));
		final int healthStatusInterval = config.getInt(NetworkConfig.Keys.HEALTH_STATUS_INTERVAL, 60); // seconds
		// this is a useful health metric that could later be exported to some kind of monitoring interface
		if (LOGGER.isLoggable(healthStatusLevel)) {
			this.scheduler = Executors.newSingleThreadScheduledExecutor(new DaemonThreadFactory("MessageExchangeStore"));
			statusLogger = scheduler.scheduleAtFixedRate(new Runnable() {
				@Override
				public void run() {
					LOGGER.log(healthStatusLevel, dumpCurrentLoadLevels());
				}
			}, healthStatusInterval, healthStatusInterval, TimeUnit.SECONDS);
		}
	}

	private String dumpCurrentLoadLevels() {
		StringBuilder b = new StringBuilder("MessageExchangeStore contents: ");
		b.append(exchangesByMID.size()).append(" exchanges by MID, ");
		b.append(exchangesByToken.size()).append(" exchanges by token, ");
		b.append(ongoingExchanges.size()).append(" ongoing blockwise exchanges");
		return b.toString();
	}

	/**
	 * Sets the object to use for detecting duplicate incoming messages.
	 * 
	 * @param deduplicator the deduplicator.
	 * @throws NullPointerException if deduplicator is {@code null}.
	 * @throws IllegalStateException if this store is already running.
	 */
	public synchronized void setDeduplicator(final Deduplicator deduplicator) {
		if (running) {
			throw new IllegalStateException("Cannot set Deduplicator when store is already started");
		} else if (deduplicator == null) {
			throw new NullPointerException("Deduplicator must not be null");
		} else {
			this.deduplicator = deduplicator;
		}
	}

	/**
	 * Sets the provider to use for creating message IDs for outbound messages.
	 * 
	 * @param provider the provider.
	 * @throws NullPointerException if provider is {@code null}.
	 * @throws IllegalStateException if this store is already running.
	 */
	public synchronized void setMessageIdProvider(final MessageIdProvider provider) {
		if (running) {
			throw new IllegalStateException("Cannot set messageIdProvider when store is already started");
		} else if (provider == null) {
			throw new NullPointerException("Message ID Provider must not be null");
		} else {
			this.messageIdProvider = provider;
		}
	}

	@Override
	public boolean isEmpty() {
		LOGGER.finer(dumpCurrentLoadLevels());
		return exchangesByMID.isEmpty() && exchangesByToken.isEmpty() && ongoingExchanges.isEmpty() &&
				deduplicator.isEmpty();
	}

	@Override
	public int assignMessageId(final Message message) {
		int mid = message.getMID();
		if (Message.NONE == mid) {
			InetSocketAddress dest = new InetSocketAddress(message.getDestination(), message.getDestinationPort());
			mid = messageIdProvider.getNextMessageId(dest);
			if (Message.NONE == mid) {
				LOGGER.log(Level.WARNING, "Cannot send message to {0}, all MIDs are in use", dest);
			} else {
				message.setMID(mid);
			}
		}
		return mid;
	}

	private int registerWithMessageId(final Exchange exchange, final Message message) {

		int mid = message.getMID();
		if (Message.NONE == mid) {
			mid = assignMessageId(message);
			if (Message.NONE != mid) {
				KeyMID key = KeyMID.fromOutboundMessage(message);
				if (exchangesByMID.putIfAbsent(key, exchange) != null) {
					LOGGER.log(Level.WARNING,
							"newly generated MID [{0}] already in use, overwriting already registered exchange", mid);
				}
			}
		} else {
			Exchange existingExchange = exchangesByMID.putIfAbsent(KeyMID.fromOutboundMessage(message), exchange);
			if (existingExchange != null) {
				if (existingExchange != exchange) {
					throw new IllegalArgumentException(String
							.format("message ID [%d] already in use, cannot register exchange", message.getMID()));
				} else if (exchange.getFailedTransmissionCount() == 0) {
					throw new IllegalArgumentException(String.format(
							"message with already registered ID [%d] is not a re-transmission, cannot register exchange",
							message.getMID()));
				}
			}
		}
		return mid;
	}

	private void registerWithToken(final Exchange exchange) {
		Request request = exchange.getCurrentRequest();
		KeyToken idByToken;
		if (request.getToken() == null) {
			idByToken = tokenProvider.getUnusedToken(request);
			request.setToken(idByToken.getToken());
		} else {
			idByToken = KeyToken.fromOutboundMessage(request);
			// ongoing requests may reuse token
			if (!(exchange.getFailedTransmissionCount() > 0 || request.getOptions().hasBlock1()
					|| request.getOptions().hasBlock2() || request.getOptions().hasObserve())
					&& tokenProvider.isTokenInUse(idByToken)) {
				LOGGER.log(Level.WARNING, "Manual token overrides existing open request: {0}", idByToken);
			}
		}
		exchangesByToken.put(idByToken, exchange);
	}

	@Override
	public boolean registerOutboundRequest(final Exchange exchange) {

		if (exchange == null) {
			throw new NullPointerException("exchange must not be null");
		} else if (exchange.getCurrentRequest() == null) {
			throw new IllegalArgumentException("exchange does not contain a request");
		} else {
			int mid = registerWithMessageId(exchange, exchange.getCurrentRequest());
			if (Message.NONE != mid) {
				registerWithToken(exchange);
				return true;
			} else {
				return false;
			}
		}
	}

	@Override
	public boolean registerOutboundRequestWithTokenOnly(final Exchange exchange) {
		if (exchange == null) {
			throw new NullPointerException("exchange must not be null");
		} else if (exchange.getCurrentRequest() == null) {
			throw new IllegalArgumentException("exchange does not contain a request");
		} else {
			registerWithToken(exchange);
			return true;
		}
	}

	@Override
	public void remove(final KeyToken token, final Exchange exchange) {
		boolean removed = exchangesByToken.remove(token, exchange);
		if (removed) {
			LOGGER.log(Level.FINE, "removing exchange for token {0}", new Object[] { token });
		}
	}

	@Override
	public Exchange remove(final KeyMID messageId, final Exchange exchange) {
		Exchange removedExchange;
		if (null == exchange) {
			removedExchange = exchangesByMID.remove(messageId);
		} else if (exchangesByMID.remove(messageId, exchange)) {
			removedExchange = exchange;
		} else {
			removedExchange = null;
		}
		if (null != removedExchange) {
			LOGGER.log(Level.FINE, "removing exchange for MID {0}", new Object[] { messageId });
		}
		return removedExchange;
	}

	@Override
	public Exchange get(final KeyToken token) {
		if (token == null) {
			return null;
		} else {
			return exchangesByToken.get(token);
		}
	}

	@Override
	public Exchange get(final KeyMID messageId) {
		if (messageId == null) {
			return null;
		} else {
			return exchangesByMID.get(messageId);
		}
	}

	@Override
	public boolean registerOutboundResponse(final Exchange exchange) {
		if (exchange == null) {
			throw new NullPointerException("exchange must not be null");
		} else if (exchange.getCurrentResponse() == null) {
			throw new IllegalArgumentException("exchange does not contain a response");
		} else {
			return registerWithMessageId(exchange, exchange.getCurrentResponse()) > Message.NONE;
		}
	}

	@Override
	public Exchange get(final KeyUri requestUri) {
		if (requestUri == null) {
			return null;
		} else {
			return ongoingExchanges.get(requestUri);
		}
	}

	@Override
	public Exchange registerBlockwiseExchange(final KeyUri requestUri, final Exchange exchange) {
		return ongoingExchanges.put(requestUri, exchange);
	}

	@Override
	public void remove(final KeyUri requestUri, final Exchange exchange) {
		if (ongoingExchanges.remove(requestUri, exchange)) {
			LOGGER.log(Level.FINE, "removing transfer for URI {0}, remaining ongoing exchanges: {1}", new Object[]{requestUri, ongoingExchanges.size()});
		}
	}

	@Override
	public synchronized void start() {
		if (!running) {
			startStatusLogging();
			if (deduplicator == null) {
				DeduplicatorFactory factory = DeduplicatorFactory.getDeduplicatorFactory();
				this.deduplicator = factory.createDeduplicator(config);
			}
			this.deduplicator.start();
			if (messageIdProvider == null) {
				LOGGER.log(Level.CONFIG, "no MessageIdProvider set, using default {0}", InMemoryMessageIdProvider.class.getName());
				messageIdProvider = new InMemoryMessageIdProvider(config);
			}
			running = true;
		}
	}

	/**
	 * Stops this store and purges all registered exchanges.
	 */
	@Override
	public synchronized void stop() {
		if (running) {
			if (statusLogger != null) {
				statusLogger.cancel(false);
			}
			deduplicator.stop();
			exchangesByMID.clear();
			exchangesByToken.clear();
			ongoingExchanges.clear();
			running = false;
		}
	}

	@Override
	public Exchange findPrevious(final KeyMID messageId, final Exchange exchange) {
		return deduplicator.findPrevious(messageId, exchange);
	}

	@Override
	public Exchange find(final KeyMID messageId) {
		return deduplicator.find(messageId);
	}
	
	@Override
	public void releaseToken(KeyToken keyToken){
		tokenProvider.releaseToken(keyToken);
	}
}
