/*******************************************************************************
 * Copyright (c) 2015 Wireless Networks Group, UPC Barcelona and i2CAT.
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
 *    August Betzler    – CoCoA implementation
 *    Matthias Kovatsch - Embedding of CoCoA in Californium
 ******************************************************************************/

package org.eclipse.californium.core.network.stack;

import java.net.InetSocketAddress;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Queue;
import java.util.Set;

import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.stack.CongestionControlLayer.PostponedExchange;
import org.eclipse.californium.core.network.stack.congestioncontrol.Cocoa;
import org.eclipse.californium.elements.EndpointIdentityResolver;

/**
 * An abstract class representing the current transmissions and parameters for a
 * specific remote endpoint.
 * 
 * @since 3.0 (moved and redesigned)
 */
public abstract class RemoteEndpoint {

	// Amounts of elements in the RTO history length
	private final static int RTOARRAYSIZE = 3;

	/**
	 * Retransmission timeout type.
	 */
	public enum RtoType {

		/**
		 * RTO from exchange without retransmission.
		 */
		STRONG,
		/**
		 * RTO from exchange with 1 or 2 retransmissions.
		 */
		WEAK,
		/**
		 * Overall RTO, calculated for {@link Cocoa} out of {@link #STRONG} and
		 * {@link #WEAK} values.
		 */
		NONE;
	}

	/**
	 * The identity of the remote endpoint.
	 * 
	 * @see EndpointIdentityResolver
	 * @since 3.8
	 */
	private final Object peersIdentity;
	/**
	 * Maximum number of concurrent transmissions.
	 */
	private final int nstart;
	/**
	 * Use blind estimator.
	 * 
	 * @see #getCurrentRTO()
	 */
	private final boolean usesBlindEstimator;

	// A concurrent Hash Set that contains the exchanges in flight
	private final Set<Exchange> inFlight;
	private final Queue<Exchange> requestQueue;
	private final Queue<Exchange> responseQueue;
	private final Queue<PostponedExchange> notifyQueue;
	/**
	 * {@code true}, if a timer for throttling notifies is already pending,
	 * {@code false}, if not.
	 */
	private boolean processingNotifies;
	/**
	 * {@code true}, if {@link #currentRTO} is already initialized,
	 * {@code false}, otherwise.
	 */
	private boolean initializedRto;
	/**
	 * Array with RTOs.
	 */
	private long[] overallRTO;
	/**
	 * Rolling index to access {@link #overallRTO}.
	 */
	private int currentOverallIndex;

	// Current RTO stores the latest updated value
	private volatile long currentRTO;
	/**
	 * Mean of {@link #overallRTO}. Some algorithms apply additional
	 * modifications for that value.
	 */
	protected long meanOverallRTO;

	/**
	 * Create a remote endpoint.
	 * 
	 * @param peersIdentity peer's identity. Usually that's the peer's
	 *            {@link InetSocketAddress}.
	 * @param ackTimeout ACK timeout
	 * @param nstart NSTARt
	 * @param usesBlindEstimator {@code true}, if blind estimator is used. A
	 *            blind estimation is based on pending exchanges until these
	 *            changes are completed.
	 * @see EndpointIdentityResolver
	 * @since 3.8 (exchanged InetSocketAddress to Object)
	 */
	public RemoteEndpoint(Object peersIdentity, int ackTimeout, int nstart, boolean usesBlindEstimator) {
		this.peersIdentity = peersIdentity;
		this.nstart = nstart;
		this.usesBlindEstimator = usesBlindEstimator;
		// Fill Array with initial values
		overallRTO = new long[RTOARRAYSIZE];
		for (int i = 0; i < RTOARRAYSIZE; i++) {
			overallRTO[i] = ackTimeout;
		}
		currentRTO = ackTimeout;

		meanOverallRTO = ackTimeout;

		currentOverallIndex = 0;

		inFlight = new HashSet<>();

		requestQueue = new LinkedList<>();
		responseQueue = new LinkedList<>();
		notifyQueue = new LinkedList<>();
	}

	/**
	 * Get identity of the remote endpoint.
	 * 
	 * @return identity of the remote endpoint
	 * @see EndpointIdentityResolver
	 * @since 3.8
	 */
	public Object getPeersIdentity() {
		return peersIdentity;
	}

	/**
	 * Get request queue.
	 * 
	 * Request must be queued, if the open transmissions reaches
	 * {@link #nstart}.
	 * 
	 * @return request queue.
	 */
	public Queue<Exchange> getRequestQueue() {
		return requestQueue;
	}

	/**
	 * Get response queue.
	 * 
	 * CON responses must be queued, if the open transmissions reaches
	 * {@link #nstart}.
	 * 
	 * @return response queue.
	 */
	public Queue<Exchange> getResponseQueue() {
		return responseQueue;
	}

	/**
	 * Get notifies queue.
	 * 
	 * Notifies must be queued, if they send are too fast.
	 * 
	 * @return notify queue.
	 */
	public Queue<PostponedExchange> getNotifyQueue() {
		return notifyQueue;
	}

	/**
	 * Set value for current RTO.
	 * 
	 * @param currentRTO current RTO in milliseconds.
	 */
	public void setCurrentRTO(long currentRTO) {
		this.currentRTO = currentRTO;
	}

	/**
	 * Get current RTO.
	 * 
	 * @return current RTO in milliseconds
	 */
	public long getCurrentRTO() {
		return currentRTO;
	}

	/**
	 * Start timer for throttling notifies.
	 * 
	 * @return {@code true}, if timer should be started, {@code false}, if timer
	 *         is already running.
	 */
	public synchronized boolean startProcessingNotifies() {
		if (processingNotifies) {
			return false;
		} else {
			processingNotifies = true;
			return true;
		}
	}

	/**
	 * Stop timer for throttling notifies.
	 * 
	 * @return {@code true}, if timer should be stopped, {@code false}, if timer
	 *         is already stopped.
	 */
	public synchronized boolean stopProcessingNotifies() {
		if (processingNotifies) {
			processingNotifies = false;
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Check for initial RTO.
	 * 
	 * If not {@link #initializedRto}, set it to {@code true} and returns
	 * {@code true} as well.
	 * 
	 * @return {@code true}, if the value is the initial RTO, {@code false}, if
	 *         RTO is already initialized.
	 */
	public synchronized boolean initialRto() {
		if (initializedRto) {
			return false;
		} else {
			initializedRto = true;
			return true;
		}
	}

	/**
	 * Obtains either blind RTO value for the next transmission (if no RTT
	 * measurements have been done so far) or gets the overall RTO (CoCoA)
	 * 
	 * @return the RTO in milliseconds
	 */
	public long getRTO() {
		long rto = currentRTO;
		int size = getNumberOfOngoingExchanges();
		if (usesBlindEstimator && size > 1 && !initializedRto) {
			// No RTT measurements have been possible so far =>
			// apply blind estimator rule
			rto *= size;
		}
		return Math.min(rto, 32000L);
	}

	/**
	 * Update stored RTO value.
	 * 
	 * @param newRTO the new RTO value
	 */
	public synchronized void updateRTO(long newRTO) {
		overallRTO[currentOverallIndex++] = newRTO;
		if (currentOverallIndex >= overallRTO.length) {
			currentOverallIndex = 0;
		}
		long meanRTO = 0;
		for (int i = 0; i < RTOARRAYSIZE; i++) {
			meanRTO += overallRTO[i];
		}
		meanOverallRTO = meanRTO / RTOARRAYSIZE;
		setCurrentRTO(newRTO);
	}

	/**
	 * Confirmable exchanges are registered at the remote endpoint.
	 * 
	 * @param exchange the exchange to register
	 * @return {@code true}, if exchange is or was registered, {@code false},
	 *         otherwise.
	 */
	public synchronized boolean registerExchange(Exchange exchange) {
		if (inFlight.contains(exchange)) {
			return true;
		} else if (inFlight.size() < nstart) {
			inFlight.add(exchange);
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Check, if exchange is already in flight.
	 * 
	 * @param exchange exchange to check.
	 * @return {@code true}, if exchange is already in flight, {@code false},
	 *         otherwise.
	 */
	public synchronized boolean inFlightExchange(Exchange exchange) {
		return inFlight.contains(exchange);
	}

	/**
	 * Removes all information of a finished exchange.
	 * 
	 * @param exchange the exchange to remove
	 * @return {@code true}, if removed
	 */
	public synchronized boolean removeExchange(Exchange exchange) {
		if (inFlight.remove(exchange)) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Gets amount of currently active exchanges
	 * 
	 * @return the count
	 */
	public synchronized int getNumberOfOngoingExchanges() {
		return inFlight.size();
	}

	/**
	 * Override this method in RTO algorithms that implement some sort of RTO
	 * aging.
	 */
	public void checkAging() {
		// empty default implementation
	}

	/**
	 * Received a new RTT measurement, evaluate it and update correspondent
	 * estimators
	 * 
	 * @param rtoType type of provided rtt
	 * @param measuredRTT the round-trip time of a CON-ACK pair
	 */
	public abstract void processRttMeasurement(RtoType rtoType, long measuredRTT);
}
