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

import org.eclipse.californium.core.network.stack.CongestionControlLayer;
import org.eclipse.californium.core.network.stack.RemoteEndpoint;
import org.eclipse.californium.elements.config.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PeakhopperRto extends CongestionControlLayer {
	/**
	 * @since 3.10
	 */
	private static final Logger LOG = LoggerFactory.getLogger(PeakhopperRto.class);

	public PeakhopperRto(String tag, Configuration config) {
		super(tag, config);
	}

	@Override
	protected RemoteEndpoint createRemoteEndpoint(Object peersIdentity) {
		return new PeakhopperRemoteEndoint(peersIdentity, defaultReliabilityLayerParameters.getAckTimeout(),
				defaultReliabilityLayerParameters.getNstart());
	}

	private static class PeakhopperRemoteEndoint extends RemoteEndpoint {

		private float delta;

		private float B_value;
		private final static float F_value = 24;
		private final static float B_max_value = 1;
		private final static float D_value = (1 - (1 / F_value));
		private final static int RTT_HISTORY_SIZE = 2;
		private long RTO_min;
		private long RTT_max;
		private long RTT_previous;
		private long[] RTT_sample = new long[RTT_HISTORY_SIZE];
		private int currentRtt;

		private PeakhopperRemoteEndoint(Object peersIdentity, int ackTimeout, int nstart) {
			super(peersIdentity, ackTimeout, nstart, true);
		}

		private void initializeRTOEstimators(long measuredRTT) {
			// Initialize peakhopper variables for the endpoint
			addRttValue(measuredRTT);
			long newRTO = (long) ((1 + 0.75) * measuredRTT);
			updateRTO(newRTO);
		}

		private void updateEstimator(long measuredRTT) {

			addRttValue(measuredRTT);
			delta = Math.abs((measuredRTT - RTT_previous) / measuredRTT);
			B_value = Math.min(Math.max(delta * 2, PeakhopperRemoteEndoint.D_value * B_value),
					PeakhopperRemoteEndoint.B_max_value);
			RTT_max = Math.max(measuredRTT, RTT_previous);
			RTO_min = getMaxRtt() + (2 * 50);

			long newRTO = (long) Math.max(PeakhopperRemoteEndoint.D_value * getRTO(), (1 + B_value) * RTT_max);
			newRTO = Math.max(Math.max(newRTO, RTT_max + (long) ((1 + PeakhopperRemoteEndoint.B_max_value) * 50)),
					RTO_min);
			printPeakhopperStats();

			RTT_previous = measuredRTT;

			updateRTO(newRTO);
		}

		@Override
		public synchronized void processRttMeasurement(RtoType rtoType, long measuredRTT) {

			if (rtoType != RtoType.STRONG) {
				return;
			}

			if (initialRto()) {
				// Received a strong RTT measurement for the first time,
				// apply strong RTO update
				initializeRTOEstimators(measuredRTT);
			} else {
				// Perform normal update of the RTO
				updateEstimator(measuredRTT);
			}
		}

		private void addRttValue(long rtt) {
			synchronized (RTT_sample) {
				RTT_sample[currentRtt++] = rtt;
				if (currentRtt >= RTT_sample.length) {
					currentRtt = 0;
				}
			}
		}

		private long getMaxRtt() {
			long max = -1;
			synchronized (RTT_sample) {
				for (long rtt : RTT_sample) {
					max = Math.max(max, rtt);
				}
			}
			return max;
		}

		private void printPeakhopperStats() {
			LOG.trace("Delta: {}, D: {}, B: {}, RTT_max: {}", delta, D_value, B_value, RTT_max);
		}
	}
}
