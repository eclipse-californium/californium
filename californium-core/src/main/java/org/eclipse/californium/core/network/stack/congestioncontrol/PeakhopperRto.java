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
 *    August Betzler    – CoCoA implementation
 *    Matthias Kovatsch - Embedding of CoCoA in Californium
 ******************************************************************************/
 
package org.eclipse.californium.core.network.stack.congestioncontrol;

import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.RemoteEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.stack.CongestionControlLayer;

public class PeakhopperRto extends CongestionControlLayer {

	private int currentRtt;
	
	
	public PeakhopperRto(NetworkConfig config) {
		super(config);
		currentRtt = 0;
	}
	
	/**
	 * Update stored RTT max value
	 *  
	 * @param endpoint the remote CoAP endpoint
	 * @param rtt the round-trip time
	 */
	public void storeRttValue(RemoteEndpoint endpoint, long rtt) {
		endpoint.RTT_sample[currentRtt] = rtt; 		
		currentRtt = (currentRtt + 1)%RemoteEndpoint.RTT_HISTORY_SIZE;
	}
	
	public long getMaxRtt(RemoteEndpoint endpoint) {
		return (endpoint.RTT_sample[0] > endpoint.RTT_sample[1]) ? endpoint.RTT_sample[0] : endpoint.RTT_sample[1];
	}
	
	@Override
	public void initializeRTOEstimators(long measuredRTT, int estimatorType, RemoteEndpoint endpoint) {
		// Initialize peakhopper variables for the endpoint	
		storeRttValue(endpoint, measuredRTT);
		long newRTO = (long)((1 + 0.75) * measuredRTT);			
		endpoint.updateRTO(newRTO);
	}
	
	@Override
	protected void updateEstimator(long measuredRTT, int estimatorType, RemoteEndpoint endpoint){

		storeRttValue(endpoint, measuredRTT);
		endpoint.delta = Math.abs((double)(measuredRTT - endpoint.RTT_previous)/measuredRTT);	
		endpoint.B_value = Math.min(Math.max(endpoint.delta * 2, RemoteEndpoint.D_value*endpoint.B_value),RemoteEndpoint.B_max_value);
		endpoint.RTT_max = Math.max(measuredRTT, endpoint.RTT_previous);
		endpoint.RTO_min = getMaxRtt(endpoint) + (2 * 50);
		
		long newRTO = (long) Math.max(RemoteEndpoint.D_value*endpoint.getRTO(), (1+endpoint.B_value) *endpoint.RTT_max);
		newRTO = Math.max(Math.max(newRTO, endpoint.RTT_max + (long) ((1 + RemoteEndpoint.B_max_value) * 50)), endpoint.RTO_min);	
		endpoint.printPeakhopperStats();
		
		endpoint.RTT_previous = measuredRTT;
			
		endpoint.updateRTO(newRTO);
	}	
	
	@Override
	public void processRTTmeasurement(long measuredRTT, Exchange exchange, int retransmissionCount){		
		
		RemoteEndpoint endpoint = getRemoteEndpoint(exchange);
		int rtoType = endpoint.getExchangeEstimatorState(exchange);
		
		if (rtoType == NOESTIMATOR || rtoType == WEAKRTOTYPE) {
			return;
		}

		//System.out.println("Measured RTT:" + measuredRTT);

		endpoint.matchCurrentRTO();
		if (endpoint.isBlindStrong() && rtoType == STRONGRTOTYPE) {
			// Received a strong RTT measurement for the first time, apply
			// strong RTO update
			endpoint.setBlindStrong(false);
			initializeRTOEstimators(measuredRTT, rtoType, endpoint);
		} else {
			// Perform normal update of the RTO
			updateEstimator(measuredRTT, rtoType, endpoint);
		}
	}

}
