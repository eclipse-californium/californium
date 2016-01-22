/*******************************************************************************
 * Copyright (c) 2015 Wireless Networks Group, UPC Barcelona and i2CAT.
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
 *    August Betzler    - CoCoA implementation
 *    Matthias Kovatsch - Embedding of CoCoA in Californium
 ******************************************************************************/
 
package org.eclipse.californium.core.network.stack.congestioncontrol;

import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.RemoteEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.stack.CongestionControlLayer;

public class BasicRto extends CongestionControlLayer {

	public BasicRto(NetworkConfig config) {
		super(config);
	}
		
	@Override
	protected void updateEstimator(long measuredRTT, int estimatorType, RemoteEndpoint endpoint){
		// Use last RTT measurement, which is then multiplied by a static factor (dithering)
		long newRTO =  measuredRTT; //; (long) (measuredRTT * 1.5);
		//System.out.println("Basic RTO: " + measuredRTT );
			
		endpoint.updateRTO(newRTO);
	}	
	
	@Override
	public void processRTTmeasurement(long measuredRTT, Exchange exchange, int retransmissionCount){		
		//System.out.println("Measured an RTT of " + measuredRTT + " after using " + retransmissionCount + " retries." );
		RemoteEndpoint endpoint = getRemoteEndpoint(exchange);
		int rtoType = endpoint.getExchangeEstimatorState(exchange);
		
		// The basic rto algorithm does not care for the blind estimator, set weak/strong to false
		endpoint.setBlindStrong(false);
		endpoint.setBlindWeak(false);
		//Perform normal update of the RTO
		updateEstimator(measuredRTT, rtoType, endpoint);

	}
}
