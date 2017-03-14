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

import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.Exchange.KeyMID;
import org.eclipse.californium.core.network.Exchange.KeyToken;
import org.eclipse.californium.core.network.Exchange.KeyUri;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.deduplication.Deduplicator;
import org.eclipse.californium.core.network.deduplication.DeduplicatorFactory;
import org.eclipse.californium.elements.CorrelationContext;


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
	private boolean running = false;
	private Deduplicator deduplicator;
	private ScheduledFuture<?> statusLogger;
	private ScheduledExecutorService scheduler;
	private MessageIdProvider messageIdProvider;
	private TokenProvider tokenProvider;
	private SecureRandom secureRandom;
	
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
			this.scheduler = Executors.newSingleThreadScheduledExecutor(new Utils.DaemonThreadFactory("MessageExchangeStore"));
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
	public void assignMessageId(final Message message) {
		if (message.getMID() == Message.NONE) {
			InetSocketAddress dest = new InetSocketAddress(message.getDestination(), message.getDestinationPort());
			int mid = messageIdProvider.getNextMessageId(dest);
			if (mid < 0) {
				LOGGER.log(Level.WARNING, "Cannot send message to {0}, all MIDs are in use", dest);
			} else {
				message.setMID(mid);
			}
		}
	}

	private void registerWithMessageId(final Exchange exchange, final Message message) {
		synchronized (messageIdProvider) {
			if (message.getMID() == Message.NONE) {
				InetSocketAddress dest = new InetSocketAddress(message.getDestination(), message.getDestinationPort());
				int mid = messageIdProvider.getNextMessageId(dest);
				if (mid < 0) {
					LOGGER.log(Level.WARNING, "Cannot send message to {0}, all MIDs are in use", dest);
				} else {
					message.setMID(mid);
					KeyMID key = KeyMID.fromOutboundMessage(message);
					if (exchangesByMID.putIfAbsent(key, exchange) != null) {
						LOGGER.log(Level.WARNING, "newly generated MID [{0}] already in use, overwriting already registered exchange",
								message.getMID());
					}
				}
			} else {
				Exchange existingExchange = exchangesByMID.putIfAbsent(KeyMID.fromOutboundMessage(message), exchange);
				if (existingExchange != null) {
					if (existingExchange != exchange) {
						throw new IllegalArgumentException(String.format("message ID [%d] already in use, cannot register exchange", message.getMID()));
					} else if (exchange.getFailedTransmissionCount() == 0) {
						throw new IllegalArgumentException(String.format("message with already registered ID [%d] is not a re-transmission, cannot register exchange",
								message.getMID()));
					}
				}
			}
		}
	}

	private void registerWithToken(final Exchange exchange) {
		Request request = exchange.getCurrentRequest();
		KeyToken idByToken;
		synchronized (exchangesByToken) {
			if (request.getToken() == null) {
				idByToken = tokenProvider.getUnusedToken(request);								
				request.setToken(idByToken.getToken());
			} else {
				idByToken = KeyToken.fromOutboundMessage(request);
				// ongoing requests may reuse token
				if (!(exchange.getFailedTransmissionCount() > 0 || request.getOptions().hasBlock1() || request.getOptions()
						.hasBlock2() || request.getOptions().hasObserve()) && tokenProvider.isTokenInUse(idByToken)) {
					LOGGER.log(Level.WARNING, "Manual token overrides existing open request: {0}", idByToken);					
				}
			}
			exchangesByToken.put(idByToken, exchange);
		}
	}

	@Override
	public void registerOutboundRequest(final Exchange exchange) {

		if (exchange == null) {
			throw new NullPointerException("exchange must not be null");
		} else if (exchange.getCurrentRequest() == null) {
			throw new IllegalArgumentException("exchange does not contain a request");
		} else {
			registerWithMessageId(exchange, exchange.getCurrentRequest());
			registerWithToken(exchange);
		}
	}

	@Override
	public void registerOutboundRequestWithTokenOnly(final Exchange exchange) {
		if (exchange == null) {
			throw new NullPointerException("exchange must not be null");
		} else if (exchange.getCurrentRequest() == null) {
			throw new IllegalArgumentException("exchange does not contain a request");
		} else {
			registerWithToken(exchange);
		}
	}

	@Override
	public void remove(final KeyToken token) {
		synchronized (exchangesByToken) {
			exchangesByToken.remove(token);
			LOGGER.log(
					Level.FINE,
					"removing exchange for token {0}, remaining exchanges by tokens: {1}",
					new Object[]{token, exchangesByToken.size()});
		}
	}

	@Override
	public Exchange remove(final KeyMID messageId) {
		synchronized (messageIdProvider) {
			Exchange removedExchange = exchangesByMID.remove(messageId);
			LOGGER.log(
					Level.FINE,
					"removing exchange for MID {0}, remaining exchanges by MIDs: {1}",
					new Object[]{messageId, exchangesByMID.size()});
			return removedExchange;
		}
	}

	@Override
	public Exchange get(final KeyToken token) {
		if (token == null) {
			return null;
		} else {
			synchronized (exchangesByToken) {
				return exchangesByToken.get(token);
			}
		}
	}

	@Override
	public Exchange get(final KeyMID messageId) {
		if (messageId == null) {
			return null;
		} else {
			synchronized (messageIdProvider) {
				return exchangesByMID.get(messageId);
			}
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * This method does nothing because all exchanges are kept in memory and thus
	 * the correlation context will already be set on the corresponding exchange object.
	 */
	@Override
	public void setContext(final KeyToken token, final CorrelationContext correlationContext) {
		// nothing to do
	}

	@Override
	public void registerOutboundResponse(final Exchange exchange) {
		if (exchange == null) {
			throw new NullPointerException("exchange must not be null");
		} else if (exchange.getCurrentResponse() == null) {
			throw new IllegalArgumentException("exchange does not contain a response");
		} else {
			registerWithMessageId(exchange, exchange.getCurrentResponse());
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

	/**
	 * Purges all registered exchanges from this store.
	 */
	public void clear() {
		synchronized (messageIdProvider) {
			synchronized (exchangesByToken) {
				exchangesByMID.clear();
				exchangesByToken.clear();
				ongoingExchanges.clear();
			}
		}
	}

	@Override
	public Exchange registerBlockwiseExchange(final KeyUri requestUri, final Exchange exchange) {
		return ongoingExchanges.put(requestUri, exchange);
	}

	@Override
	public void remove(final KeyUri requestUri) {
		synchronized(ongoingExchanges) {
			ongoingExchanges.remove(requestUri);
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
			secureRandom = new SecureRandom();
			secureRandom.nextInt(10); // trigger self-seeding of the PRNG
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
			clear();
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
