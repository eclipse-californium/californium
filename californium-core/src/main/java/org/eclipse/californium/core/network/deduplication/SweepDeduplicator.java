/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.core.network.deduplication;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.KeyMID;
import org.eclipse.californium.core.network.config.NetworkConfig;


/**
 * This deduplicator uses a hash map to store incoming messages. The
 * deduplicator periodically iterates through all entries and removes obsolete
 * messages (exchanges).
 */
public class SweepDeduplicator implements Deduplicator {

	/** The logger. */
	private final static Logger LOGGER = Logger.getLogger(SweepDeduplicator.class.getCanonicalName());
	
	/** The hash map with all incoming messages. */
	private ConcurrentHashMap<KeyMID, Exchange> incommingMessages;
	
	private NetworkConfig config;
	private SweepAlgorithm algorithm;
	
	private ScheduledExecutorService executor;
	
	private boolean started = false;
	
	public SweepDeduplicator(NetworkConfig config) {
		this.config = config;
		incommingMessages = new ConcurrentHashMap<KeyMID, Exchange>();
		algorithm = new SweepAlgorithm();
	}
	
	public void start() {
		started = true;
		algorithm.schedule();
	}
	
	public void stop() {
		started = false;
		algorithm.cancel();
	}
	
	public void setExecutor(ScheduledExecutorService executor) {
		stop();
		this.executor = executor;
		if (started)
			start();
	}
	
	/**
	 * If the message with the specified {@link KeyMID} has already arrived
	 * before, this method returns the corresponding exchange. If this
	 * KeyMID has not yet arrived, this method returns null, indicating that
	 * the message with the KeyMID is not a duplicate. In this case, the
	 * exchange is added to the deduplicator.
	 */
	public Exchange findPrevious(KeyMID key, Exchange exchange) {
		Exchange previous = incommingMessages.putIfAbsent(key, exchange);
		return previous;
	}
	
	public Exchange find(KeyMID key) {
		return incommingMessages.get(key);
	}
	
	public void clear() {
		incommingMessages.clear();
	}
	
	/**
	 * The sweep algorithm periodically iterate through the hash map and removes
	 * obsolete entries.
	 */
	private class SweepAlgorithm implements Runnable {

		private ScheduledFuture<?> future;
		
		/**
		 * This method wraps the method sweep() to catch any Exceptions that
		 * might be thrown.
		 */
		@Override
		public void run() {
			try {
				LOGGER.finest("Start Mark-And-Sweep with "+incommingMessages.size()+" entries");
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
			int lifecycle = config.getInt(NetworkConfig.Keys.EXCHANGE_LIFETIME);
			long oldestAllowed = System.currentTimeMillis() - lifecycle;
			
			// Notice that the guarantees from the ConcurrentHashMap guarantee
			// the correctness for this iteration.
			for (Map.Entry<?,Exchange> entry:incommingMessages.entrySet()) {
				Exchange exchange = entry.getValue();
				if (exchange.getTimestamp() < oldestAllowed) {
					//TODO check if exchange of observe relationship is periodically created and sweeped
					LOGGER.finer("Mark-And-Sweep removes "+entry.getKey());
					incommingMessages.remove(entry.getKey());
				}
			}
		}
		
		/**
		 * Reschedule this task again.
		 */
		private void schedule() {
			long period = config.getLong(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL);
			future = executor.schedule(this, period, TimeUnit.MILLISECONDS);
		}
		
		/**
		 * Cancel the schedule for this algorithm.
		 */
		private void cancel() {
			if (future != null)
				future.cancel(true);
		}
		
	}
}
