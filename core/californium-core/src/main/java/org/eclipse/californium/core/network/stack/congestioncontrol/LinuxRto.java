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

public class LinuxRto extends CongestionControlLayer{

	public LinuxRto(NetworkConfig config) {
		super(config);
	}
	
	@Override
	public void initializeRTOEstimators(long measuredRTT, int estimatorType, RemoteEndpoint endpoint){		
			
		long RTT 	  	  = measuredRTT;				
		endpoint.SRTT	  = RTT;
		endpoint.mdev	  = RTT/2;
		endpoint.mdev_max = Math.max(endpoint.mdev, 50);
		endpoint.RTTVAR	  = endpoint.mdev_max;
		long newRTO		  = endpoint.SRTT + 4 * endpoint.RTTVAR;
		endpoint.printLinuxStats();

		endpoint.updateRTO(newRTO);
	}
	
	@Override
	protected void updateEstimator(long measuredRTT, int estimatorType, RemoteEndpoint endpoint){
		//System.out.println("Measured RTT:" + measuredRTT);
		long RTT = measuredRTT;		
		
		endpoint.SRTT = endpoint.SRTT + Math.round((double)(0.125 * (RTT - endpoint.SRTT)));

		if (RTT < endpoint.SRTT - endpoint.mdev){
			endpoint.mdev = Math.round(0.96875 * endpoint.mdev) + Math.round((double) 0.03125 * Math.abs(RTT - endpoint.SRTT));
		}else{
			endpoint.mdev = Math.round((double) 0.75   * endpoint.mdev) + Math.round((double) 0.25  * Math.abs(RTT - endpoint.SRTT));
		}
		if (endpoint.mdev > endpoint.mdev_max) {
			endpoint.mdev_max = endpoint.mdev;
			 if (endpoint.mdev_max > endpoint.RTTVAR)
				 endpoint.RTTVAR = endpoint.mdev_max;
		}

		if (endpoint.mdev_max < endpoint.RTTVAR)
			 endpoint.RTTVAR = Math.round((double)(0.75 * endpoint.RTTVAR)) + Math.round((double)(0.25 * endpoint.mdev_max));
		 
		endpoint.mdev_max = 50;
		long newRTO = endpoint.SRTT + 4 * endpoint.RTTVAR;
		
		endpoint.printLinuxStats();		
		
		endpoint.updateRTO(newRTO);
	}	
	
	@Override
	public void processRTTmeasurement(long measuredRTT, Exchange exchange, int retransmissionCount){		
		RemoteEndpoint endpoint = getRemoteEndpoint(exchange);
		int rtoType = endpoint.getExchangeEstimatorState(exchange);
		
		if(rtoType == NOESTIMATOR || rtoType == WEAKRTOTYPE )
			return;
		
		// System.out.println("Measured RTT:" + measuredRTT);
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
