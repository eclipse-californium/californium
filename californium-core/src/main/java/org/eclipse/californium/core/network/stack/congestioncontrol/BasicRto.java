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
		// Use last RTT measurement multiplied by a static factor as RTO for the next transmission
		long newRTO = (long) (measuredRTT * 1.5);
		System.out.println("Basic RTO - Measured RTT: " + measuredRTT + " RTO for next transmission: " + newRTO);
			
		endpoint.updateRTO(newRTO);
	}	
	
	@Override
	public void processRTTmeasurement(long measuredRTT, Exchange exchange, int retransmissionCount){		
		//System.out.println("Measured an RTT of " + measuredRTT + " after using " + retransmissionCount + " retries." );
		RemoteEndpoint endpoint = getRemoteEndpoint(exchange);
		int rtoType = endpoint.getExchangeEstimatorState(exchange);
		
		//Perform normal update of the RTO
		updateEstimator(measuredRTT, rtoType, endpoint);

	}
}
