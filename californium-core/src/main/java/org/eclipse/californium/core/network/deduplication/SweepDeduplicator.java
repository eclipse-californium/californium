/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - use timestamp of add for deduplication 
 ******************************************************************************/
package org.eclipse.californium.core.network.deduplication;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.KeyMID;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.util.DaemonThreadFactory;

/**
 * This deduplicator uses an in-memory map to store incoming messages.
 * <p>
 * The deduplicator periodically iterates through all entries and removes
 * messages (exchanges) that have been received before EXCHANGE_LIFETIME seconds.
 * </p>
 */
public final class SweepDeduplicator implements Deduplicator {

	private final static Logger LOGGER = Logger.getLogger(SweepDeduplicator.class.getName());

	/**
	 * Add timestamp for deduplication to Exchange.
	 */
	private static class DedupExchange {

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
			this.nanoTimestamp = System.nanoTime();
		}
	}
	
	/** The hash map with all incoming messages. */
	private final ConcurrentMap<KeyMID, DedupExchange> incomingMessages = new ConcurrentHashMap<>();
	private final SweepAlgorithm algorithm;
	private ScheduledExecutorService scheduler;
	private boolean running = false;

	/**
	 * Creates a new deduplicator from configuration values.
	 * <p>
	 * The following configuration values are used to initialize the
	 * sweep algorithm used by this deduplicator:
	 * <ul>
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#EXCHANGE_LIFETIME} -
	 * an exchange is removed from this deduplicator if no messages have been received for this number
	 * of milliseconds</li>
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#MARK_AND_SWEEP_INTERVAL} -
	 * the interval at which to check for expired exchanges in milliseconds</li>
	 * </ul>
	 * 
	 * @param config the configuration to use.
	 */
	public SweepDeduplicator(final NetworkConfig config) {
		algorithm = new SweepAlgorithm(config);
	}

	@Override
	public synchronized void start() {
		if (!running) {
			if (scheduler == null || scheduler.isShutdown()) {
				scheduler = Executors.newSingleThreadScheduledExecutor(new DaemonThreadFactory("Deduplicator"));
			}
			algorithm.schedule();
			running = true;
		}
	}

	@Override
	public synchronized void stop() {
		if (running) {
			algorithm.cancel();
			scheduler.shutdown();
			clear();
			running = false;
		}
	}

	/**
	 * If the message with the specified {@link KeyMID} has already arrived
	 * before, this method returns the corresponding exchange. If this
	 * KeyMID has not yet arrived, this method returns null, indicating that
	 * the message with the KeyMID is not a duplicate. In this case, the
	 * exchange is added to the deduplicator.
	 */
	@Override
	public Exchange findPrevious(final KeyMID key, final Exchange exchange) {
		DedupExchange previous = incomingMessages.putIfAbsent(key, new DedupExchange(exchange));
		return null == previous ? null : previous.exchange;
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

	/**
	 * The sweep algorithm periodically iterates over all exchanges and removes
	 * obsolete entries.
	 */
	private class SweepAlgorithm implements Runnable {

		private final long sweepInterval;
		private final long exchangeLifetime;
		private ScheduledFuture<?> future;

		/**
		 * @param config
		 */
		public SweepAlgorithm(final NetworkConfig config) {
			this.exchangeLifetime = config.getLong(NetworkConfig.Keys.EXCHANGE_LIFETIME);
			this.sweepInterval = config.getLong(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL);
		}

		/**
		 * This method wraps the method sweep() to catch any Exceptions that
		 * might be thrown.
		 */
		@Override
		public void run() {
			try {
				LOGGER.log(Level.FINEST, "Start Mark-And-Sweep with {0} entries", incomingMessages.size());
				sweep();

			} catch (Throwable t) {
				LOGGER.log(Level.WARNING, "Exception in Mark-and-Sweep algorithm", t);

			} finally {
				try {
					schedule();
				} catch (Throwable t) {
					LOGGER.log(Level.WARNING, "Exception while scheduling Mark-and-Sweep algorithm", t);
				}
			}
		}

		/**
		 * Iterate through all entries and remove the obsolete ones.
		 */
		private void sweep() {
			
			final long start = System.nanoTime();
			final long oldestAllowed = start - TimeUnit.MILLISECONDS.toNanos(exchangeLifetime);

			// Notice that ConcurrentHashMap guarantees the correctness for this iteration.
			for (Map.Entry<?, DedupExchange> entry : incomingMessages.entrySet()) {
				DedupExchange exchange = entry.getValue();
				if (exchange.nanoTimestamp < oldestAllowed) {
					//TODO check if exchange of observe relationship is periodically created and sweeped
					LOGGER.log(Level.FINER, "Mark-And-Sweep removes {0}", entry.getKey());
					incomingMessages.remove(entry.getKey());
				}
			}
			LOGGER.log(Level.FINE, "Sweep run took {0}ms", TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start));
		}

		/**
		 * Reschedule this task again.
		 */
		private void schedule() {
			if (!scheduler.isShutdown()) {
				future = scheduler.schedule(this, sweepInterval, TimeUnit.MILLISECONDS);
			}
		}

		/**
		 * Cancels sweep-run scheduled next.
		 */
		private void cancel() {
			if (future != null) {
				future.cancel(false);
			}
		}
	}
}
