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
 *    Achim Kraus (Bosch Software Innovations GmbH) - adjust to use Token
 *                                                    use token generator instead
 *                                                    of provider. Remove not longer
 *                                                    required releaseToken.
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 *    Achim Kraus (Bosch Software Innovations GmbH) - start status logging with first
 *                                                    stored exchange. 
 *                                                    Add exchange dump to status.
 *    Achim Kraus (Bosch Software Innovations GmbH) - check for modified current requests
 *                                                    or responses.
 *    Achim Kraus (Bosch Software Innovations GmbH) - move retransmitResponse to
 *                                                    CoapEndpoint to support tcp.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use ExecutorsUtil.getScheduledExecutor()
 *                                                    for health status instead of own executor.
 *    Achim Kraus (Bosch Software Innovations GmbH) - cancel not acknowledged requests on stop().
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.Exchange.KeyMID;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaults;
import org.eclipse.californium.core.network.deduplication.Deduplicator;
import org.eclipse.californium.core.network.deduplication.DeduplicatorFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;

/**
 * A {@code MessageExchangeStore} that manages all exchanges in local memory.
 */
public class InMemoryMessageExchangeStore implements MessageExchangeStore {

	private static final Logger LOGGER = LoggerFactory.getLogger(InMemoryMessageExchangeStore.class.getName());
	private static final Logger HEALTH_LOGGER = LoggerFactory.getLogger(LOGGER.getName() + ".health");
	// for all
	private final ConcurrentMap<KeyMID, Exchange> exchangesByMID = new ConcurrentHashMap<>();
	// for outgoing
	private final ConcurrentMap<Token, Exchange> exchangesByToken = new ConcurrentHashMap<>();
	private volatile boolean enableStatus;

	private final NetworkConfig config;
	private final TokenGenerator tokenGenerator;
	private volatile boolean running = false;
	private volatile Deduplicator deduplicator;
	private volatile MessageIdProvider messageIdProvider;
	private ScheduledFuture<?> statusLogger;

	/**
	 * Creates a new store for configuration values.
	 * 
	 * @param config the configuration to use.
	 * 
	 */
	public InMemoryMessageExchangeStore(final NetworkConfig config) {
		this(config, new RandomTokenGenerator(config));
		LOGGER.debug("using default TokenProvider {}", RandomTokenGenerator.class.getName());
	}

	/**
	 * Creates a new store for configuration values.
	 * 
	 * @param config the configuration to use.
	 * @param tokenProvider the TokenProvider which provides CoAP tokens that
	 *            are guaranteed to be not in use.
	 * 
	 */
	public InMemoryMessageExchangeStore(final NetworkConfig config, TokenGenerator tokenProvider) {
		if (config == null) {
			throw new NullPointerException("Configuration must not be null");
		}
		if (tokenProvider == null) {
			throw new NullPointerException("TokenProvider must not be null");
		}
		this.tokenGenerator = tokenProvider;
		this.config = config;
	}

	private void startStatusLogging() {

		final int healthStatusInterval = config.getInt(NetworkConfig.Keys.HEALTH_STATUS_INTERVAL, NetworkConfigDefaults.DEFAULT_HEALTH_STATUS_INTERVAL); // seconds
		// this is a useful health metric
		// that could later be exported to some kind of monitoring interface
		if (healthStatusInterval > 0 && HEALTH_LOGGER.isDebugEnabled()) {
			statusLogger = ExecutorsUtil.getScheduledExecutor().scheduleAtFixedRate(new Runnable() {

				@Override
				public void run() {
					if (enableStatus) {
						dump(5);
					}
				}
			}, healthStatusInterval, healthStatusInterval, TimeUnit.SECONDS);
		}
	}

	private String dumpCurrentLoadLevels() {
		StringBuilder b = new StringBuilder("MessageExchangeStore contents: ");
		b.append(exchangesByMID.size()).append(" exchanges by MID, ");
		b.append(exchangesByToken.size()).append(" exchanges by token, ");
		b.append(deduplicator.size()).append(" MIDs, ");
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

	private int registerWithMessageId(final Exchange exchange, final Message message) {
		enableStatus = true;
		exchange.assertIncomplete(message);
		int mid = message.getMID();
		if (Message.NONE == mid) {
			mid = assignMessageId(message);
			if (Message.NONE != mid) {
				KeyMID key = KeyMID.fromOutboundMessage(message);
				if (exchangesByMID.putIfAbsent(key, exchange) != null) {
					throw new IllegalArgumentException(String.format(
							"generated mid [%d] already in use, cannot register %s", message.getMID(), exchange));
				}
				LOGGER.debug("{} added with generated mid {}, {}", exchange, key, message);
			}
		} else {
			KeyMID key = KeyMID.fromOutboundMessage(message);
			Exchange existingExchange = exchangesByMID.putIfAbsent(key, exchange);
			if (existingExchange != null) {
				if (existingExchange != exchange) {
					throw new IllegalArgumentException(
							String.format("mid [%d] already in use, cannot register %s", message.getMID(), exchange));
				} else if (exchange.getFailedTransmissionCount() == 0) {
					throw new IllegalArgumentException(String.format(
							"message with already registered mid [%d] is not a re-transmission, cannot register %s",
							message.getMID(), exchange));
				}
			} else {
				LOGGER.debug("{} added with {}, {}", exchange, key, message);
			}
		}
		return mid;
	}

	private void registerWithToken(final Exchange exchange) {
		enableStatus = true;
		Request request = exchange.getCurrentRequest();
		exchange.assertIncomplete(request);
		Token token = request.getToken();
		if (token == null) {
			do {
				token = tokenGenerator.createToken(false);
				request.setToken(token);
			} while (exchangesByToken.putIfAbsent(token, exchange) != null);
			LOGGER.debug("{} added with generated token {}, {}", exchange, token, request);
		} else {
			// ongoing requests may reuse token
			if (token.isEmpty() && request.getCode() == null) {
				// ping, no exchange by token required!
				return;
			}
			Exchange previous = exchangesByToken.put(token, exchange);
			if (previous == null) {
				BlockOption block2 = request.getOptions().getBlock2();
				if (block2 != null) {
					LOGGER.debug("block2 {} for block {} add with token {}", exchange, block2.getNum(), token);
				} else {
					LOGGER.debug("{} added with token {}, {}", exchange, token, request);
				}
			} else if (previous != exchange) {
				if (exchange.getFailedTransmissionCount() == 0 && !request.getOptions().hasBlock1()
						&& !request.getOptions().hasBlock2() && !request.getOptions().hasObserve()) {
					LOGGER.warn("{} with manual token overrides existing {} with open request: {}", exchange, previous,
							token);
				} else {
					LOGGER.debug("{} replaced with token {}, {}", exchange, token, request);
				}
			} else {
				LOGGER.debug("{} keep for {}, {}", exchange, token, request);
			}
		}
	}

	@Override
	public boolean registerOutboundRequest(final Exchange exchange) {

		if (exchange == null) {
			throw new NullPointerException("exchange must not be null");
		} else if (exchange.getCurrentRequest() == null) {
			throw new IllegalArgumentException("exchange does not contain a request");
		} else {
			Request currentRequest = exchange.getCurrentRequest();
			int mid = registerWithMessageId(exchange, currentRequest);
			if (Message.NONE != mid) {
				registerWithToken(exchange);
				if (exchange.getCurrentRequest() != currentRequest) {
					throw new ConcurrentModificationException("Current request modified!");
				}
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
			Request currentRequest = exchange.getCurrentRequest();
			registerWithToken(exchange);
			if (exchange.getCurrentRequest() != currentRequest) {
				throw new ConcurrentModificationException("Current request modified!");
			}
			return true;
		}
	}

	@Override
	public void remove(final Token token, final Exchange exchange) {
		boolean removed = exchangesByToken.remove(token, exchange);
		if (removed) {
			LOGGER.debug("removing {} for token {}", exchange, token);
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
			LOGGER.debug("removing {} for MID {}", removedExchange, messageId);
		}
		return removedExchange;
	}

	@Override
	public Exchange get(final Token token) {
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
			Response currentResponse = exchange.getCurrentResponse();
			if (registerWithMessageId(exchange, currentResponse) > Message.NONE) {
				if (exchange.getCurrentResponse() != currentResponse) {
					throw new ConcurrentModificationException("Current response modified!");
				}
				return true;
			} else {
				return false;
			}
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
				LOGGER.debug("no MessageIdProvider set, using default {}", InMemoryMessageIdProvider.class.getName());
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
			running = false;
			for (Exchange exchange : exchangesByMID.values()) {
				exchange.getRequest().setCanceled(true);
			}
			if (statusLogger != null) {
				statusLogger.cancel(false);
				statusLogger = null;
			}
			deduplicator.stop();
			exchangesByMID.clear();
			exchangesByToken.clear();
		}
	}

	/**
	 * Dump exchanges of stores.
	 * 
	 * @param logMaxExchanges maximum number of exchanges to include in dump.
	 */
	public void dump(int logMaxExchanges) {
		if (HEALTH_LOGGER.isDebugEnabled()) {
			HEALTH_LOGGER.debug(dumpCurrentLoadLevels());
			if (0 < logMaxExchanges) {
				if (!exchangesByMID.isEmpty()) {
					dumpExchanges(logMaxExchanges, exchangesByMID.entrySet());
				}
				if (!exchangesByToken.isEmpty()) {
					dumpExchanges(logMaxExchanges, exchangesByToken.entrySet());
				}
			}
		}
	}

	/**
	 * Dump collection of exchange entries.
	 * 
	 * @param logMaxExchanges maximum number of exchanges to include in dump.
	 * @param exchangeEntries collection with exchanges entries
	 */
	private <K> void dumpExchanges(int logMaxExchanges, Set<Entry<K, Exchange>> exchangeEntries) {
		for (Entry<K, Exchange> exchangeEntry : exchangeEntries) {
			Exchange exchange = exchangeEntry.getValue();
			Request origin = exchange.getRequest();
			Request current = exchange.getCurrentRequest();
			String pending = exchange.getRetransmissionHandle() == null ? "" : "/pending";
			if (origin != current && !origin.getToken().equals(current.getToken())) {
				HEALTH_LOGGER.debug("  {}, {}, retransmission {}{}, org {}, {}, {}", exchangeEntry.getKey(),
						exchange, exchange.getFailedTransmissionCount(), pending, origin.getToken(),
						current, exchange.getCurrentResponse());
			} else {
				String mark = origin == null ? "(missing origin request) " : "";
				HEALTH_LOGGER.debug("  {}, {}, retransmission {}{}, {}{}, {}", exchangeEntry.getKey(),
						exchange, exchange.getFailedTransmissionCount(), pending, mark, current,
						exchange.getCurrentResponse());
			}
			Throwable caller = exchange.getCaller();
			if (caller != null) {
				HEALTH_LOGGER.trace("  ", caller);
			}
			if (0 >= --logMaxExchanges) {
				break;
			}
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
	public List<Exchange> findByToken(Token token) {
		List<Exchange> result = new ArrayList<>();
		if (token != null) {
			// TODO: remove the for ...
			for (Entry<Token, Exchange> entry : exchangesByToken.entrySet()) {
				if (entry.getValue().isOfLocalOrigin()) {
					Request request = entry.getValue().getRequest();
					if (request != null && token.equals(request.getToken())) {
						result.add(entry.getValue());
					}
				}
			}
		}
		return result;
	}
}
