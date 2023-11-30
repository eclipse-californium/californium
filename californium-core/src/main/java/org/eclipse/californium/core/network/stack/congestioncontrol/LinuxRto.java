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

public class LinuxRto extends CongestionControlLayer {
	/**
	 * @since 3.10
	 */
	private static final Logger LOG = LoggerFactory.getLogger(LinuxRto.class);

	public LinuxRto(String tag, Configuration config) {
		super(tag, config);
	}

	@Override
	protected RemoteEndpoint createRemoteEndpoint(Object peersIdentity) {
		return new LinuxRemoteEndpoint(peersIdentity, defaultReliabilityLayerParameters.getAckTimeout(),
				defaultReliabilityLayerParameters.getNstart());
	}

	private static class LinuxRemoteEndpoint extends RemoteEndpoint {

		/* Linux algorithm variables FOR TESTING ONLY */
		private long SRTT;
		private long RTTVAR;
		private long mdev;
		private long mdev_max;

		private LinuxRemoteEndpoint(Object peersIdentity, int ackTimeout, int nstart) {
			super(peersIdentity, ackTimeout, nstart, true);
		}

		private void initializeRTOEstimators(long measuredRTT) {
			long RTT = measuredRTT;
			SRTT = RTT;
			mdev = RTT / 2;
			mdev_max = Math.max(mdev, 50);
			RTTVAR = mdev_max;
			long newRTO = SRTT + 4 * RTTVAR;
			printLinuxStats();

			updateRTO(newRTO);
		}

		private void updateEstimator(long measuredRTT) {
			// System.out.println("Measured RTT:" + measuredRTT);
			long RTT = measuredRTT;

			SRTT = SRTT + Math.round((double) (0.125 * (RTT - SRTT)));

			if (RTT < SRTT - mdev) {
				mdev = Math.round(0.96875 * mdev + 0.03125 * Math.abs(RTT - SRTT));
			} else {
				mdev = Math.round(0.75 * mdev) + Math.round(0.25 * Math.abs(RTT - SRTT));
			}
			if (mdev > mdev_max) {
				mdev_max = mdev;
				if (mdev_max > RTTVAR) {
					RTTVAR = mdev_max;
				}
			}

			if (mdev_max < RTTVAR) {
				RTTVAR = Math.round(0.75 * RTTVAR + 0.25 * mdev_max);
			}
			mdev_max = 50;
			long newRTO = SRTT + 4 * RTTVAR;

			printLinuxStats();

			updateRTO(newRTO);
		}

		@Override
		public synchronized void processRttMeasurement(RtoType rtoType, long measuredRTT) {

			if (rtoType != RtoType.STRONG) {
				return;
			}

			if (initialRto()) {
				// Received a strong RTT measurement for the first time, apply
				// strong RTO update
				initializeRTOEstimators(measuredRTT);
			} else {
				// Perform normal update of the RTO
				updateEstimator(measuredRTT);
			}
		}

		private void printLinuxStats() {
			LOG.trace("SRTT: {}, RTTVAR: {}, mdev: {}, mdev_max: {}", SRTT, RTTVAR, mdev, mdev_max);
		}
	}
}
