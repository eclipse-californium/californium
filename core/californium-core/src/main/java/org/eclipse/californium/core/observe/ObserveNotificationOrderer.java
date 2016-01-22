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
package org.eclipse.californium.core.observe;

import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.coap.Response;


/**
 * The ObservingNotificationOrderer holds the state of an observe relation such
 * as the timeout of the last notification and the current number.
 */
public class ObserveNotificationOrderer {

	/** The counter for observe numbers */
	private AtomicInteger number;
	
	/** The timestamp of the last response */
	private long timestamp;
	
	/**
	 * Creates a new notification orderer.
	 */
	public ObserveNotificationOrderer() {
		this.number = new AtomicInteger();
	}
	
	/**
	 * Return a new observe option number. This method is thread-safe as it
	 * increases the option number atomically.
	 * 
	 * @return a new observe option number
	 */
	public int getNextObserveNumber() {
		int next = number.incrementAndGet();
		while (next >= 1<<24) {
			number.compareAndSet(next, 0);
			next = number.incrementAndGet();
		}
		// assert 0 <= next && next < 1<<24;
		return next;
	}
	
	/**
	 * Returns the current notification number.
	 * @return the current notification number
	 */
	public int getCurrent() {
		return number.get();
	}
	
	/**
	 * Returns the current timeout.
	 * @return the current timeout
	 */
	public long getTimestamp() {
		return timestamp;
	}

	/**
	 * Sets the current timestamp.
	 * @param timestamp the timestamp
	 */
	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}
	
	/**
	 * Returns true if the specified notification is newer than the current one.
	 * @param response the notification
	 * @return true if the notification is new
	 */
	public synchronized boolean isNew(Response response) {
		
		if (!response.getOptions().hasObserve()) {
			// this is a final response, e.g., error or proactive cancellation
			return true;
		}
		
		// Multiple responses with different notification numbers might
		// arrive and be processed by different threads. We have to
		// ensure that only the most fresh one is being delivered.
		// We use the notation from the observe draft-08.
		long T1 = getTimestamp();
		long T2 = System.currentTimeMillis();
		int V1 = getCurrent();
		int V2 = response.getOptions().getObserve();
		if (V1 < V2 && V2 - V1 < 1<<23
				|| V1 > V2 && V1 - V2 > 1<<23
				|| T2 > T1 + 128000) {

			setTimestamp(T2);
			number.set(V2);
			return true;
		} else {
			return false;
		}
	}
}
