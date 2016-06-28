/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.KeyMID;
import org.eclipse.californium.core.network.config.NetworkConfig;


/**
 * This deduplicator is probably inferior to the {@link SweepDeduplicator}. This
 * deduplicator holds three hash maps, two of which are always active and one is
 * passive. After an EXCHANGE_LIFECYCLE, the hash maps switch their places by
 * one. When a message arrives, the deduplicator adds it to the two active hash
 * maps. Therefore, it is remembered for at least one lifecycle and at most two.
 * This deduplicator adds most messages to two hash maps but does not need to
 * remove them one-by-one. Instead, it clears all entries of the passive
 * hash map at once.
 */
public class CropRotation implements Deduplicator {

	private final static Logger LOGGER = Logger.getLogger(CropRotation.class.getCanonicalName());
	private boolean running = false;
	private ScheduledExecutorService executor;

	private ExchangeMap[] maps;
	private int first;
	private int second;

	private long period;
	private Rotation rotation;

	/**
	 * Creates a new crop rotation deduplicator for configuration properties.
	 * <p>
	 * Uses the value of the {@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#CROP_ROTATION_PERIOD}
	 * param from the given configuration as the waiting period between crop rotation (in milliseconds).
	 * 
	 * @param config The configuration properties.
	 */
	public CropRotation(NetworkConfig config) {
		this.rotation = new Rotation();
		maps = new ExchangeMap[3];
		maps[0] = new ExchangeMap();
		maps[1] = new ExchangeMap();
		maps[2] = new ExchangeMap();
		first = 0;
		second = 1;
		period = config.getInt(NetworkConfig.Keys.CROP_ROTATION_PERIOD);
	}

	@Override
	public synchronized void start() {
		if (!running) {
			if (executor == null || executor.isShutdown()) {
				executor = Executors.newSingleThreadScheduledExecutor(new Utils.DaemonThreadFactory("Deduplicator"));
			}
			rotation.schedule();
			running = true;
		}
	}

	@Override
	public synchronized void stop() {
		if (running) {
			rotation.cancel();
			executor.shutdown();
			clear();
			running = false;
		}
	}

	@Override
	public Exchange findPrevious(KeyMID key, Exchange exchange) {
		int f = first;
		int s = second;
		Exchange prev = maps[f].putIfAbsent(key, exchange);
		if (prev != null || f==s) 
			return prev;
		prev = maps[s].putIfAbsent(key, exchange);
		return prev;
	}

	@Override
	public Exchange find(KeyMID key) {
		int f = first;
		int s = second;
		Exchange prev = maps[f].get(key);
		if (prev != null || f==s)
			return prev;
		prev = maps[s].get(key);
		return prev;
	}

	@Override
	public void clear() {
		synchronized (maps) {
			maps[0].clear();
			maps[1].clear();
			maps[2].clear();
		}
	}

	@Override
	public boolean isEmpty() {
		for (ExchangeMap map : maps) {
			if (!map.isEmpty()) {
				return false;
			}
		}
		return true;
	}

	private class Rotation implements Runnable {
		
		private ScheduledFuture<?> future;
		
		public void run() {
			try {
				rotation();
			} catch (Throwable t) {
				LOGGER.log(Level.WARNING, "Exception in Crop-Rotation algorithm", t);
			
			} finally {
				try {
					schedule();
				} catch (Throwable t) {
					LOGGER.log(Level.WARNING, "Exception while scheduling Crop-Rotation algorithm", t);
				}
			}
		}
		
		private void rotation() {
			synchronized (maps) {
				int third = first;
				first = second;
				second = (second+1)%3;
				maps[third].clear();
			}
		}
		
		private void schedule() {
			if (!executor.isShutdown()) {
				LOGGER.log(Level.FINE, "CR schedules in {0} ms", period);
				future = executor.schedule(this, period, TimeUnit.MILLISECONDS);
			}
		}

		private void cancel() {
			if (future != null) {
				future.cancel(true);
			}
		}
	}
	
	private static class ExchangeMap extends ConcurrentHashMap<KeyMID, Exchange> {
		private static final long serialVersionUID = 1504940670839294042L;
	}
}
