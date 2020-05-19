/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.network.deduplication;

import java.util.Iterator;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.network.KeyMID;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.util.ClockUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This deduplicator uses an in-memory map to store incoming messages per peer.
 * <p>
 * The deduplicator periodically iterates through all entries and removes
 * messages (exchanges) that have been received before EXCHANGE_LIFETIME
 * seconds. If new messages from peer are recevied exceeding the message limit,
 * old mesasges are removed even before their lifetime.
 * </p>
 * 
 * @since 2.3
 */
public final class SweepPerPeerDeduplicator extends SweepDeduplicator {

	private final static Logger LOGGER = LoggerFactory.getLogger(SweepPerPeerDeduplicator.class);

	/** The hash map with all incoming messages. */
	private final ConcurrentMap<Object, Queue<KeyMID>> incomingPerPeerMessages = new ConcurrentHashMap<>();
	private final int messagePerPeer;

	/**
	 * Creates a new deduplicator from configuration values.
	 * <p>
	 * The following configuration values are used to initialize the sweep
	 * algorithm used by this deduplicator:
	 * <ul>
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#PEERS_MARK_AND_SWEEP_MESSAGES}
	 * - maximum number of messages per peer kept for deduplication.</li>
	 * </ul>
	 * 
	 * See {@link SweepDeduplicator#SweepDeduplicator(NetworkConfig)} for other
	 * used configuration values.
	 * 
	 * @param config the configuration to use.
	 */
	public SweepPerPeerDeduplicator(NetworkConfig config) {
		super(config);
		algorithm = new SweepAlgorithm();
		messagePerPeer = config.getInt(NetworkConfig.Keys.PEERS_MARK_AND_SWEEP_MESSAGES);
	}

	@Override
	protected void onAdd(KeyMID key, boolean replace) {
		Object peer = key.getPeer();
		Queue<KeyMID> peersQueue = incomingPerPeerMessages.get(peer);
		if (peersQueue == null) {
			peersQueue = new ArrayBlockingQueue<KeyMID>(messagePerPeer);
			peersQueue.add(key);
			Queue<KeyMID> temp = incomingPerPeerMessages.putIfAbsent(peer, peersQueue);
			if (temp == null) {
				// new queue added => return
				return;
			}
			peersQueue = temp;
		}
		if (replace) {
			peersQueue.remove(key);
		}
		while (!peersQueue.offer(key)) {
			KeyMID oldest = peersQueue.poll();
			incomingMessages.remove(oldest);
		}
		return;
	}

	/**
	 * Remove the key from the queue.
	 * 
	 * Only removes the same key, but not a only equal key.
	 * 
	 * @param peersQueue queue to remove the key
	 * @param key key to be removed
	 */
	private void removeSame(Queue<KeyMID> peersQueue, KeyMID key) {
		Iterator<KeyMID> iterator = peersQueue.iterator();
		while (iterator.hasNext()) {
			if (iterator.next() == key) {
				iterator.remove();
				break;
			}
		}
	}

	@Override
	public void clear() {
		super.clear();
		incomingPerPeerMessages.clear();
	}

	/**
	 * The sweep algorithm periodically iterates over all exchanges and removes
	 * obsolete entries.
	 */
	private class SweepAlgorithm implements Runnable {

		private int lastSizeDiff;

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
				int size = incomingMessages.size();
				int queueSize = 0;
				int missingExchanges = 0;
				// Notice that ConcurrentHashMap guarantees the correctness for
				// this iteration.
				for (Map.Entry<?, Queue<KeyMID>> entry : incomingPerPeerMessages.entrySet()) {
					Queue<KeyMID> queue = entry.getValue();
					if (queue.isEmpty()) {
						incomingPerPeerMessages.remove(entry.getKey());
					} else {
						queueSize += queue.size();
						KeyMID key;
						while ((key = queue.peek()) != null) {
							DedupExchange exchange = incomingMessages.get(key);
							long diff = exchange == null ? -1 : exchange.nanoTimestamp - oldestAllowed;
							if (diff < 0) {
								if (exchange != null) {
									incomingMessages.remove(key, exchange);
									LOGGER.trace("Mark-And-Sweep removes {}", key);
								} else {
									++missingExchanges;
								}
								removeSame(queue, key);
							} else {
								if (LOGGER.isTraceEnabled()) {
									LOGGER.trace("Time left {}ms", TimeUnit.NANOSECONDS.toMillis(diff));
								}
								break;
							}
						}
					}
				}
				LOGGER.debug("Sweep run took {}ms", TimeUnit.NANOSECONDS.toMillis(ClockUtil.nanoRealtime() - start));
				if (missingExchanges > 0) {
					LOGGER.warn("{} exchanges missing", missingExchanges);
				}
				int diff = size - queueSize;
				if (Math.abs(lastSizeDiff) > 1000 && Math.abs(diff) > 1000) {
					LOGGER.info("Map size {} differs from queues size {}!", size, queueSize);
				}
				lastSizeDiff = diff;
			}
		}
	}
}
