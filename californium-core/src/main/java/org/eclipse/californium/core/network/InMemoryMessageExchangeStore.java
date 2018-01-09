/*******************************************************************************
 * Copyright (c) 2016, 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - adjust to use Token and KeyToken
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 *    Achim Kraus (Bosch Software Innovations GmbH) - use key token factory
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.Exchange.KeyMID;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.deduplication.Deduplicator;
import org.eclipse.californium.core.network.deduplication.DeduplicatorFactory;
import org.eclipse.californium.elements.util.DaemonThreadFactory;

/**
 * A {@code MessageExchangeStore} that manages all exchanges in local memory.
 *
 */
public class InMemoryMessageExchangeStore implements MessageExchangeStore {

	private static final Logger LOGGER = LoggerFactory.getLogger(InMemoryMessageExchangeStore.class.getName());
	// for all
	private final ConcurrentMap<KeyMID, Exchange> exchangesByMID = new ConcurrentHashMap<>();
	// for outgoing
	private final ConcurrentMap<KeyToken, Exchange> exchangesByToken = new ConcurrentHashMap<>();

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
		LOGGER.info("using default TokenProvider {}", InMemoryRandomTokenProvider.class.getName());
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

		final int healthStatusInterval = config.getInt(NetworkConfig.Keys.HEALTH_STATUS_INTERVAL, 60); // seconds
		// this is a useful health metric
		// that could later be exported to some kind of monitoring interface
		if (LOGGER.isTraceEnabled()) {
			this.scheduler = Executors
					.newSingleThreadScheduledExecutor(new DaemonThreadFactory("MessageExchangeStore"));
			statusLogger = scheduler.scheduleAtFixedRate(new Runnable() {

				@Override
				public void run() {
					LOGGER.trace(dumpCurrentLoadLevels());
				}
			}, healthStatusInterval, healthStatusInterval, TimeUnit.SECONDS);
		}
	}

	private String dumpCurrentLoadLevels() {
		StringBuilder b = new StringBuilder("MessageExchangeStore contents: ");
		b.append(exchangesByMID.size()).append(" exchanges by MID, ");
		b.append(exchangesByToken.size()).append(" exchanges by token, ");
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
		return exchangesByMID.isEmpty() && exchangesByToken.isEmpty() && deduplicator.isEmpty();
	}

	@Override
	public String toString() {
		return dumpCurrentLoadLevels();
	}

	@Override
	public int assignMessageId(final Message message) {
		int mid = message.getMID();
		if (Message.NONE == mid) {
			InetSocketAddress dest = message.getDestinationContext().getPeerAddress();
			mid = messageIdProvider.getNextMessageId(dest);
			if (Message.NONE == mid) {
				LOGGER.warn("cannot send message to {}, all MIDs are in use", dest);
			} else {
				message.setMID(mid);
			}
		}
		return mid;
	}

	@Override
	public Token assignToken(Message message) {
		Token token = message.getToken();
		if (token == null) {
			token = tokenProvider.getUnusedToken();
			message.setToken(token);
		} else {
			// ongoing requests may reuse token
			if (!(message.getOptions().hasBlock1()
				|| message.getOptions().hasBlock2() || message.getOptions().hasObserve())
				&& tokenProvider.isTokenInUse(token)) {
				LOGGER.warn("manual token overrides existing open request: {}", token);
			}
		}
		return token;
	}

	private int registerWithMessageId(final Exchange exchange, final Message message) {

		int mid = message.getMID();
		if (Message.NONE == mid) {
			mid = assignMessageId(message);
			if (Message.NONE != mid) {
				KeyMID key = KeyMID.fromOutboundMessage(message);
				if (exchangesByMID.putIfAbsent(key, exchange) != null) {
					LOGGER.warn("newly generated MID [{}] already in use, overwriting already registered exchange", mid);
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

	private void registerWithToken(KeyTokenFactory keyTokenFactory, final Exchange exchange) {
		Request request = exchange.getCurrentRequest();
		Token token = request.getToken();
		if (token == null) {
			token = tokenProvider.getUnusedToken();
			request.setToken(token);
		} else {
			// ongoing requests may reuse token
			if (!(exchange.getFailedTransmissionCount() > 0 || request.getOptions().hasBlock1()
					|| request.getOptions().hasBlock2() || request.getOptions().hasObserve())
					&& tokenProvider.isTokenInUse(token)) {
				LOGGER.warn("manual token overrides existing open request: {}", token);
			}
		}
		KeyToken idByToken = keyTokenFactory.create(token, exchange.getEndpointContext());
		exchangesByToken.put(idByToken, exchange);
	}

	@Override
	public boolean registerOutboundRequest(KeyTokenFactory keyTokenFactory, final Exchange exchange) {

		if (exchange == null) {
			throw new NullPointerException("exchange must not be null");
		} else if (exchange.getCurrentRequest() == null) {
			throw new IllegalArgumentException("exchange does not contain a request");
		} else {
			int mid = registerWithMessageId(exchange, exchange.getCurrentRequest());
			if (Message.NONE != mid) {
				registerWithToken(keyTokenFactory, exchange);
				return true;
			} else {
				return false;
			}
		}
	}

	@Override
	public boolean registerOutboundRequestWithTokenOnly(KeyTokenFactory keyTokenFactory, final Exchange exchange) {
		if (exchange == null) {
			throw new NullPointerException("exchange must not be null");
		} else if (exchange.getCurrentRequest() == null) {
			throw new IllegalArgumentException("exchange does not contain a request");
		} else {
			registerWithToken(keyTokenFactory, exchange);
			return true;
		}
	}

	@Override
	public void remove(final KeyToken keyToken, final Exchange exchange) {
		boolean removed = exchangesByToken.remove(keyToken, exchange);
		if (removed) {
			LOGGER.debug("removing exchange for token {}", keyToken);
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
			LOGGER.debug("removing exchange for MID {}", messageId);
		}
		return removedExchange;
	}

	@Override
	public Exchange get(final KeyToken keyToken) {
		if (keyToken == null) {
			return null;
		} else {
			return exchangesByToken.get(keyToken);
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
	public synchronized void start() {
		if (!running) {
			startStatusLogging();
			if (deduplicator == null) {
				DeduplicatorFactory factory = DeduplicatorFactory.getDeduplicatorFactory();
				this.deduplicator = factory.createDeduplicator(config);
			}
			this.deduplicator.start();
			if (messageIdProvider == null) {
				LOGGER.info("no MessageIdProvider set, using default {}",
						InMemoryMessageIdProvider.class.getName());
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
	public List<Exchange> findByToken(KeyToken keyToken) {
		List<Exchange> result = new ArrayList<>();
		if (keyToken != null) {
			// TODO: remove the for ... 
			for (Entry<KeyToken, Exchange> entry : exchangesByToken.entrySet()) {
				if (entry.getValue().isOfLocalOrigin()) {
					Request request = entry.getValue().getRequest();
					// TODO: change to use KeyTokenFactory for request token
					if (request != null && keyToken.getToken().equals(request.getToken())) {
						result.add(entry.getValue());
					}
				}
			}
		}
		return result;
	}

	@Override
	public void releaseToken(Token token) {
		tokenProvider.releaseToken(token);
	}

	protected Map<KeyToken, Exchange> getExchangesByToken() {
		return exchangesByToken;
	}

	protected Map<KeyMID, Exchange> getExchangesByMID() {
		return exchangesByMID;
	}

	protected Deduplicator getDeduplicator() {
		return deduplicator;
	}
}
