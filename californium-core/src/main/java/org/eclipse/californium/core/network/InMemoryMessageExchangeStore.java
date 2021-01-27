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
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.TokenGenerator.Scope;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaults;
import org.eclipse.californium.core.network.deduplication.Deduplicator;
import org.eclipse.californium.core.network.deduplication.DeduplicatorFactory;
import org.eclipse.californium.elements.EndpointIdentityResolver;
import org.eclipse.californium.elements.UdpEndpointContextMatcher;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * A {@code MessageExchangeStore} that manages all exchanges in local memory.
 */
public class InMemoryMessageExchangeStore implements MessageExchangeStore {

	private static final Logger LOGGER = LoggerFactory.getLogger(InMemoryMessageExchangeStore.class);
	private static final Logger HEALTH_LOGGER = LoggerFactory.getLogger(LOGGER.getName() + ".health");
	// for all
	private final ConcurrentMap<KeyMID, Exchange> exchangesByMID = new ConcurrentHashMap<>();
	// for outgoing
	private final ConcurrentMap<KeyToken, Exchange> exchangesByToken = new ConcurrentHashMap<>();
	private volatile boolean enableStatus;

	private final NetworkConfig config;
	private final TokenGenerator tokenGenerator;
	private final EndpointIdentityResolver endpointIdentityResolver;
	private final String tag;
	private volatile boolean running = false;
	private volatile Deduplicator deduplicator;
	private volatile MessageIdProvider messageIdProvider;
	private ScheduledExecutorService executor;
	private ScheduledFuture<?> statusLogger;

	/**
	 * Creates a new store for configuration values.
	 * 
	 * @param config the configuration to use.
	 * 
	 * @throws NullPointerException if config is {@code null}
	 */
	public InMemoryMessageExchangeStore(NetworkConfig config) {
		this(null, config, new RandomTokenGenerator(config), new UdpEndpointContextMatcher());
	}

	/**
	 * Creates a new store for configuration values.
	 * 
	 * @param config the configuration to use.
	 * @param tokenProvider the TokenProvider which provides CoAP tokens.
	 * @param endpointResolver the endpoint resolver which provides endpoint
	 *            identity.
	 * @throws NullPointerException if one or the parameter is {@code null}
	 */
	public InMemoryMessageExchangeStore(NetworkConfig config, TokenGenerator tokenProvider,
			EndpointIdentityResolver endpointResolver) {
		this(null, config, tokenProvider, endpointResolver);
	}

	public InMemoryMessageExchangeStore(String tag, NetworkConfig config, TokenGenerator tokenProvider,
			EndpointIdentityResolver endpointResolver) {
		if (config == null) {
			throw new NullPointerException("Configuration must not be null");
		}
		if (tokenProvider == null) {
			throw new NullPointerException("TokenProvider must not be null");
		}
		if (endpointResolver == null) {
			throw new NullPointerException("EndpointContextResolver must not be null");
		}
		this.tokenGenerator = tokenProvider;
		this.endpointIdentityResolver = endpointResolver;
		this.config = config;
		this.tag = StringUtil.normalizeLoggingTag(tag);
		LOGGER.debug("{}using TokenProvider {}", tag, tokenProvider.getClass().getName());
	}

	private void startStatusLogging() {
		final int healthStatusInterval = config.getInt(NetworkConfig.Keys.HEALTH_STATUS_INTERVAL, NetworkConfigDefaults.DEFAULT_HEALTH_STATUS_INTERVAL); // seconds
		// this is a useful health metric
		// that could later be exported to some kind of monitoring interface
		if (healthStatusInterval > 0 && HEALTH_LOGGER.isDebugEnabled() && executor != null) {
			statusLogger = executor.scheduleAtFixedRate(new Runnable() {

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
		StringBuilder b = new StringBuilder(tag);
		b.append("MessageExchangeStore contents: ");
		b.append(exchangesByMID.size()).append(" exchanges by MID, ");
		b.append(exchangesByToken.size()).append(" exchanges by token, ");
		b.append(deduplicator.size()).append(" MIDs.");
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
	public synchronized void setExecutor(ScheduledExecutorService executor) {
		if (running) {
			throw new IllegalStateException("Cannot set messageIdProvider when store is already started");
		} else {
			this.executor = executor;
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
			try {
				mid = messageIdProvider.getNextMessageId(dest);
				message.setMID(mid);
			} catch (IllegalStateException ex) {
				String code = CoAP.toCodeString(message.getRawCode());
				LOGGER.warn("{}cannot send message {}-{} to {}, {}", tag, message.getType(), code,
						StringUtil.toLog(dest), ex.getMessage());
			}
		}
		return mid;
	}

	private KeyMID registerWithMessageId(final Exchange exchange, final Message message) {
		enableStatus = true;
		exchange.assertIncomplete(message);
		Object peer = endpointIdentityResolver.getEndpointIdentity(message.getDestinationContext());
		KeyMID key;
		int mid = message.getMID();
		if (Message.NONE == mid) {
			mid = assignMessageId(message);
			if (Message.NONE != mid) {
				key = new KeyMID(mid, peer);
				if (exchangesByMID.putIfAbsent(key, exchange) != null) {
					throw new IllegalArgumentException(String.format(
							"generated mid [%d] already in use, cannot register %s", mid, exchange));
				}
				LOGGER.debug("{}{} added with generated mid {}, {}", tag, exchange, key, message);
			} else {
				key = null;
			}
		} else {
			key = new KeyMID(mid, peer);
			Exchange existingExchange = exchangesByMID.putIfAbsent(key, exchange);
			if (existingExchange != null) {
				if (existingExchange != exchange) {
					throw new IllegalArgumentException(
							String.format("mid [%d] already in use, cannot register %s", mid, exchange));
				} else if (exchange.getFailedTransmissionCount() == 0) {
					throw new IllegalArgumentException(String.format(
							"message with already registered mid [%d] is not a re-transmission, cannot register %s",
							mid, exchange));
				}
			} else {
				LOGGER.debug("{}{} added with {}, {}", tag, exchange, key, message);
			}
		}
		if (key != null) {
			exchange.setKeyMID(key);
		}
		return key;
	}

	private void registerWithToken(final Exchange exchange) {
		enableStatus = true;
		Request request = exchange.getCurrentRequest();
		exchange.assertIncomplete(request);
		Object peer = endpointIdentityResolver.getEndpointIdentity(request.getDestinationContext());
		KeyToken key;
		Token token = request.getToken();
		if (token == null) {
			Scope scope = request.isMulticast() ? Scope.SHORT_TERM : Scope.SHORT_TERM_CLIENT_LOCAL;
			do {
				token = tokenGenerator.createToken(scope);
				request.setToken(token);
				key = tokenGenerator.getKeyToken(token, peer);
			} while (exchangesByToken.putIfAbsent(key, exchange) != null);
			LOGGER.debug("{}{} added with generated token {}, {}", tag, exchange, key, request);
		} else {
			// ongoing requests may reuse token
			if (token.isEmpty() && request.getCode() == null) {
				// ping, no exchange by token required!
				return;
			}
			key = tokenGenerator.getKeyToken(token, peer);
			Exchange previous = exchangesByToken.put(key, exchange);
			if (previous == null) {
				BlockOption block2 = request.getOptions().getBlock2();
				if (block2 != null) {
					LOGGER.debug("{}block2 {} for block {} add with token {}", tag, exchange, block2.getNum(), key);
				} else {
					LOGGER.debug("{}{} added with token {}, {}", tag, exchange, key, request);
				}
			} else if (previous != exchange) {
				if (exchange.getFailedTransmissionCount() == 0 && !request.getOptions().hasBlock1()
						&& !request.getOptions().hasBlock2() && !request.getOptions().hasObserve()) {
					LOGGER.warn("{}{} with manual token overrides existing {} with open request: {}", tag, exchange,
							previous, key);
				} else {
					LOGGER.debug("{}{} replaced with token {}, {}", tag, exchange, key, request);
				}
			} else {
				LOGGER.debug("{}{} keep for {}, {}", tag, exchange, key, request);
			}
		}
		if (key != null) {
			exchange.setKeyToken(key);
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
			KeyMID key = registerWithMessageId(exchange, currentRequest);
			if (key != null) {
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
	public void remove(final KeyToken token, final Exchange exchange) {
		boolean removed = exchangesByToken.remove(token, exchange);
		if (removed) {
			LOGGER.debug("{}removing {} for token {}", tag, exchange, token);
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
			LOGGER.debug("{}removing {} for MID {}", tag, removedExchange, messageId);
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
			Response currentResponse = exchange.getCurrentResponse();
			if (registerWithMessageId(exchange, currentResponse) != null) {
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
			this.deduplicator.setExecutor(executor);
			this.deduplicator.start();
			if (messageIdProvider == null) {
				LOGGER.debug("{}no MessageIdProvider set, using default {}", tag, InMemoryMessageIdProvider.class.getName());
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
	public boolean replacePrevious(KeyMID key, Exchange previous, Exchange exchange) {
		return deduplicator.replacePrevious(key, previous, exchange);
	}

	@Override
	public Exchange find(final KeyMID messageId) {
		return deduplicator.find(messageId);
	}

	@Override
	public List<Exchange> findByToken(Token token) {
		List<Exchange> result = new ArrayList<>();
		if (token != null) {
			if (tokenGenerator.getScope(token) == Scope.SHORT_TERM_CLIENT_LOCAL) {
				throw new IllegalArgumentException("token must not have client-local scope!");
			}
			// TODO: remove the for ...
			for (Entry<KeyToken, Exchange> entry : exchangesByToken.entrySet()) {
				if (entry.getValue().isOfLocalOrigin()) {
					Request request = entry.getValue().getRequest();
					if (request != null) {
						if (token.equals(request.getToken())) {
							result.add(entry.getValue());
						}
					}
				}
			}
		}
		return result;
	}
}
