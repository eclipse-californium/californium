/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 *                                                    explicit String concatenation
 *    Achim Kraus (Bosch Software Innovations GmbH) - use nanoTime instead of 
 *                                                    currentTimeMillis
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix used milliseconds calculation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add size() for test-logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - use timestamp of add for deduplication 
 *    Achim Kraus (Bosch Software Innovations GmbH) - reduce logging for empty deduplicator.
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - change logging level for removed entries
 *                                                    from debug to trace
 *    Achim Kraus (Bosch Software Innovations GmbH) - use ExecutorsUtil.getScheduledExecutor()
 *                                                    instead of own executor.
 ******************************************************************************/
package org.eclipse.californium.core.network.deduplication;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.KeyMID;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.ClockUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This deduplicator uses an in-memory map to store incoming messages.
 * <p>
 * The deduplicator periodically iterates through all entries and removes
 * messages (exchanges) that have been received before EXCHANGE_LIFETIME
 * seconds.
 * </p>
 */
public class SweepDeduplicator implements Deduplicator {

	private final static Logger LOGGER = LoggerFactory.getLogger(SweepDeduplicator.class);

	/**
	 * Add timestamp for deduplication to Exchange. For special processing of
	 * notifies, a notify exchange is stored for deduplication with multiple
	 * MIDs, each represents a notify and its send time, but the exchange is
	 * always the freshest.
	 */
	static class DedupExchange {

		/**
		 * Nano-timestamp for deduplication of Exchange.
		 */
		public final long nanoTimestamp;
		/**
		 * Exchange to be deduplicated.
		 */
		public final Exchange exchange;

		/**
		 * Create new exchange for deduplication.
		 * 
		 * @param exchange Exchange to be deduplicated
		 */
		public DedupExchange(Exchange exchange) {
			this.exchange = exchange;
			this.nanoTimestamp = ClockUtil.nanoRealtime();
		}

		@Override
		public int hashCode() {
			return exchange.hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			} else if (obj == null) {
				return false;
			} else if (getClass() != obj.getClass()) {
				return false;
			}
			DedupExchange other = (DedupExchange) obj;
			return exchange.equals(other.exchange);
		}
	}

	/** The hash map with all incoming messages. */
	final ConcurrentMap<KeyMID, DedupExchange> incomingMessages = new ConcurrentHashMap<>();
	final long exchangeLifetime;
	final boolean replace;
	Runnable algorithm;

	private final long sweepInterval;
	private volatile ScheduledFuture<?> jobStatus;
	private ScheduledExecutorService executor;

	/**
	 * Creates a new deduplicator from configuration values.
	 * <p>
	 * The following configuration values are used to initialize the
	 * sweep algorithm used by this deduplicator:
	 * <ul>
	 * <li>{@link CoapConfig#EXCHANGE_LIFETIME} -
	 * an exchange is removed from this deduplicator if no messages have been received for this number
	 * of milliseconds</li>
	 * <li>{@link CoapConfig#MARK_AND_SWEEP_INTERVAL} -
	 * the interval at which to check for expired exchanges in milliseconds</li>
	 * <li>{@link CoapConfig#DEDUPLICATOR_AUTO_REPLACE} -
	 * the flag to enable exchange replacing, if the new exchange differs from the already stored one.</li>
	 * </ul>
	 * 
	 * @param config the configuration to use.
	 * @since 3.0 (changed parameter to Configuration)
	 */
	public SweepDeduplicator(Configuration config) {
		sweepInterval = config.get(CoapConfig.MARK_AND_SWEEP_INTERVAL, TimeUnit.MILLISECONDS);
		exchangeLifetime = config.get(CoapConfig.EXCHANGE_LIFETIME, TimeUnit.MILLISECONDS);
		replace = config.get(CoapConfig.DEDUPLICATOR_AUTO_REPLACE);
	}

	@Override
	public synchronized void start() {
		if (algorithm == null) {
			algorithm = new SweepAlgorithm();
		}
		if (jobStatus == null) {
			jobStatus = executor.scheduleAtFixedRate(algorithm, sweepInterval, sweepInterval, TimeUnit.MILLISECONDS);
		}
	}

	@Override
	public synchronized void stop() {
		if (jobStatus != null) {
			jobStatus.cancel(false);
			jobStatus = null;
			clear();
		}
	}

	@Override
	public synchronized void setExecutor(ScheduledExecutorService executor) {
		if (jobStatus != null)
			throw new IllegalStateException("executor service can not be set on running Deduplicator");
		this.executor = executor;
	}

	/**
	 * If the message with the specified {@link KeyMID} has already arrived
	 * before, this method returns the corresponding exchange. If this
	 * KeyMID has not yet arrived, this method returns null, indicating that
	 * the message with the KeyMID is not a duplicate. In this case, the
	 * exchange is added to the deduplicator.
	 * Calls {@link #onAdd(KeyMID, boolean)}, if exchange was added.
	 */
	@Override
	public Exchange findPrevious(final KeyMID key, final Exchange exchange) {
		DedupExchange current = new DedupExchange(exchange);
		DedupExchange previous = incomingMessages.putIfAbsent(key, current);

		boolean replaced = false;
		if (replace && previous != null && previous.exchange.getOrigin() != exchange.getOrigin()) {
			if (incomingMessages.replace(key, previous, current)) {
				LOGGER.debug("replace exchange for {}", key);
				previous = null;
				replaced = true;
			} else {
				// previous has changed
				previous = incomingMessages.putIfAbsent(key, current);
			}
		}

		if (previous == null) {
			LOGGER.debug("add exchange for {}", key);
			onAdd(key, replaced);
			return null;
		} else {
			LOGGER.debug("found exchange for {}", key);
			return previous.exchange;
		}
	}

	@Override
	public boolean replacePrevious(KeyMID key, Exchange previous, Exchange exchange) {
		boolean replaced = true;
		boolean result = true;
		DedupExchange prev = new DedupExchange(previous);
		DedupExchange current = new DedupExchange(exchange);
		if (!incomingMessages.replace(key, prev, current)) {
			replaced = false;
			result = incomingMessages.putIfAbsent(key, current) == null;
		}
		if (result) {
			onAdd(key, replaced);
		}
		return result;
	}

	@Override
	public Exchange find(KeyMID key) {
		DedupExchange previous = incomingMessages.get(key);
		return null == previous ? null : previous.exchange;
	}

	@Override
	public void clear() {
		incomingMessages.clear();
	}

	@Override
	public boolean isEmpty() {
		return incomingMessages.isEmpty();
	}

	@Override
	public int size() {
		return incomingMessages.size();
	}

	/**
	 * Called when a MID key was added.
	 * 
	 * @param key added key
	 * @param replace {@code true}, if the added key replaces a existing one,
	 *            {@code false}, if not.
	 * @since 2.3
	 */
	protected void onAdd(KeyMID key, boolean replace) {
		// empty default implementation
	}

	/**
	 * The sweep algorithm periodically iterates over all exchanges and removes
	 * obsolete entries.
	 */
	private class SweepAlgorithm implements Runnable {

		/**
		 * This method wraps the method sweep() to catch any Exceptions that
		 * might be thrown.
		 */
		@Override
		public void run() {
			try {
				LOGGER.trace("Start Mark-And-Sweep with {} entries", incomingMessages.size());
				sweep();

			} catch (Throwable t) {
				LOGGER.warn("Exception in Mark-and-Sweep algorithm", t);
			}
		}

		/**
		 * Iterate through all entries and remove the obsolete ones.
		 */
		private void sweep() {

			if (!incomingMessages.isEmpty()) {
				final long start = ClockUtil.nanoRealtime();
				final long oldestAllowed = start - TimeUnit.MILLISECONDS.toNanos(exchangeLifetime);

				// Notice that ConcurrentHashMap guarantees the correctness for this iteration.
				for (Map.Entry<?, DedupExchange> entry : incomingMessages.entrySet()) {
					DedupExchange exchange = entry.getValue();
					if ((exchange.nanoTimestamp - oldestAllowed) < 0) {
						//TODO check if exchange of observe relationship is periodically created and sweeped
						LOGGER.trace("Mark-And-Sweep removes {}", entry.getKey());
						incomingMessages.remove(entry.getKey());
					}
				}
				LOGGER.debug("Sweep run took {}ms", TimeUnit.NANOSECONDS.toMillis(ClockUtil.nanoRealtime() - start));
			}
		}
	}
}
