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
 *    August Betzler    - CoCoA implementation
 *    Matthias Kovatsch - Embedding of CoCoA in Californium
 ******************************************************************************/

package org.eclipse.californium.core.network.stack.congestioncontrol;

import org.eclipse.californium.core.network.stack.CongestionControlLayer;
import org.eclipse.californium.core.network.stack.RemoteEndpoint;
import org.eclipse.californium.elements.config.Configuration;

public class BasicRto extends CongestionControlLayer {

	public BasicRto(String tag, Configuration config) {
		super(tag, config);
	}

	@Override
	protected RemoteEndpoint createRemoteEndpoint(Object peersIdentity) {
		return new RemoteEndpoint(peersIdentity, defaultReliabilityLayerParameters.getAckTimeout(),
				defaultReliabilityLayerParameters.getNstart(), false) {

			@Override
			public void processRttMeasurement(RtoType rtoType, long measuredRTT) {
				// Perform normal update of the RTO
				updateRTO(measuredRTT + measuredRTT / 2);
			}
		};
	}

}
