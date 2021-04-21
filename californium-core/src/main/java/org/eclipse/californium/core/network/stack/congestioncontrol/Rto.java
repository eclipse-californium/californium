/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial creation
 ******************************************************************************/

package org.eclipse.californium.core.network.stack.congestioncontrol;

/**
 * Retransmission timeout calculator.
 * 
 * @see <a href="https://tools.ietf.org/html/rfc6298" target="_blank"> RFC6298 -
 *      Computing TCP's Retransmission Timer</a>
 * @since 3.0
 */
public class Rto {

	private final static double ALPHA = 0.25;
	private final static double BETA = 0.125;

	private final static int G = 100; // timer granularity 100ms

	private final int kFactor;

	private boolean init;
	private long rto;
	private long rtt;
	private long rttVar;

	/**
	 * Create RTO calculator
	 * 
	 * @param kFactor k-factor, usually {@code 4}.
	 * @param ackTimeout acknowledge timeout in milliseconds.
	 */
	public Rto(int kFactor, long ackTimeout) {
		this.kFactor = kFactor;
		this.rtt = 0;
		this.rttVar = 0;
		this.rto = ackTimeout;
	}

	/**
	 * Apply measured RTT.
	 * 
	 * @param measuredRTT measured RTT in milliseconds.
	 * @return calculated retransmission timeout in milliseconds.
	 */
	public long apply(long measuredRTT) {
		long RTTVAR;
		long RTT;
		if (init) {
			RTTVAR = Math.round((1 - BETA) * this.rttVar + BETA * Math.abs(this.rtt - measuredRTT));
			RTT = Math.round((1 - ALPHA) * this.rtt + ALPHA * measuredRTT);
		} else {
			init = true;
			RTTVAR = measuredRTT / 2;
			RTT = measuredRTT;
		}
		this.rtt = RTT;
		this.rttVar = RTTVAR;
		this.rto = RTT + Math.max(G, kFactor * RTTVAR);
		return rto;
	}

	/**
	 * Get calculated retransmission timeout.
	 * 
	 * Initial value is the provided
	 * 
	 * @return calculated retransmission timeout in milliseconds
	 */
	public long getRto() {
		return rto;
	}

	/**
	 * Get smoothed round trip time.
	 * 
	 * @return smoothed round trip time in milliseconds.
	 */
	public long getRtt() {
		return rtt;
	}

	/**
	 * Get round trip time variation.
	 * 
	 * @return round trip time variation in milliseconds
	 */
	public long getRttVar() {
		return rttVar;
	}

}
