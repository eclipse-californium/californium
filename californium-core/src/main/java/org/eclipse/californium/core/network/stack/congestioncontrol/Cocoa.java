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

package org.eclipse.californium.core.network.stack.congestioncontrol;

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.network.stack.CongestionControlLayer;
import org.eclipse.californium.core.network.stack.RemoteEndpoint;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.ClockUtil;

public class Cocoa extends CongestionControlLayer {

	private final static int KSTRONG = 4;
	private final static int KWEAK = 1;

	private final static double STRONGWEIGHTING = 0.5;
	private final static double WEAKWEIGHTING = 0.25;

	// determines the threshold for RTOs to be considered "small"
	private final static long LOWERVBFLIMIT = 1000;
	// determines the threshold for RTOs to be considered "large"
	private final static long UPPERVBFLIMIT = 3000;
	private final static float VBFLOW = 3;
	private final static float VBFHIGH = 1.5F;

	// Not used for the current version of CoCoA
	// private final static long UPPERAGELIMIT = 30000; // determines after how
	// long (ms) an estimator undergoes the aging process

	private final boolean strong;

	public Cocoa(String tag, Configuration config, boolean strong) {
		super(tag, config);
		this.strong = strong;
		setDithering(true);
	}

	@Override
	protected RemoteEndpoint createRemoteEndpoint(Object peersIdentity) {
		return new CocoaRemoteEndpoint(peersIdentity, defaultReliabilityLayerParameters.getAckTimeout(),
				defaultReliabilityLayerParameters.getNstart(), strong);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * CoCoA applies a variable backoff factor (VBF) to retransmissions,
	 * depending on the RTO value of the first transmission of the CoAP request.
	 */
	@Override
	protected float calculateVBF(long rto, float scale) {
		if (rto > UPPERVBFLIMIT) {
			return VBFHIGH;
		}
		if (rto < LOWERVBFLIMIT) {
			return VBFLOW;
		}
		return scale;
	}

	private static class CocoaRemoteEndpoint extends RemoteEndpoint {

		private final boolean onlyStrong;
		private Rto weakRto;
		private Rto strongRto;
		private long nanoTimestamp;

		private CocoaRemoteEndpoint(Object peersIdentity, int ackTimeout, int nstart, boolean strong) {
			super(peersIdentity, ackTimeout, nstart, true);
			this.onlyStrong = strong;
			this.weakRto = new Rto(KWEAK, ackTimeout);
			this.strongRto = new Rto(KSTRONG, ackTimeout);
			this.nanoTimestamp = ClockUtil.nanoRealtime();
		}

		@Override
		public synchronized void processRttMeasurement(RtoType rtoType, long measuredRTT) {
			if (onlyStrong && rtoType != RtoType.STRONG) {
				return;
			}

			long newRto;
			double weighting;
			switch (rtoType) {
			case WEAK:
				newRto = weakRto.apply(measuredRTT);
				weighting = WEAKWEIGHTING;
				break;
			case STRONG:
				newRto = strongRto.apply(measuredRTT);
				weighting = STRONGWEIGHTING;
				break;
			default:
				return;
			}
			newRto = Math.round(weighting * newRto + (1 - weighting) * getRTO());
			updateRTO(newRto);
			this.nanoTimestamp = ClockUtil.nanoRealtime();
		}

		/**
		 * Aging check: 1.) If the overall estimator has a value below 1 s and
		 * 16*RTO seconds pass without an update, double the value of the RTO
		 * (apply cumulatively!) 2.) If the overall estimator has a value above
		 * 3 s and 4*RTO seconds pass without an update, reduce its value
		 */
		@Override
		public synchronized void checkAging() {

			long overallDifference = getRtoAge(TimeUnit.MILLISECONDS);

			long rto = getRTO();
			while (true) {
				if (rto < LOWERVBFLIMIT && overallDifference > (16 * rto)) {
					overallDifference -= (16 * rto);
					// Increase mean overall RTO, if condition 1) is true
					rto *= 2;
					updateRTO(rto);
					this.nanoTimestamp = ClockUtil.nanoRealtime();
				} else if (rto > UPPERVBFLIMIT && overallDifference > (4 * rto)) {
					overallDifference -= (4 * rto);
					// Decrease mean overall RTO if condition 2) is true
					rto = 1000 + rto / 2;
					updateRTO(rto);
					this.nanoTimestamp = ClockUtil.nanoRealtime();
				} else {
					break;
				}
			}
		}

		private long getRtoAge(TimeUnit unit) {
			long nanos = ClockUtil.nanoRealtime() - nanoTimestamp;
			return unit.convert(nanos, TimeUnit.NANOSECONDS);
		}
	}
}
