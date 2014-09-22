package org.eclipse.californium.core.network.stack.congestioncontrol;

import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.RemoteEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.stack.CongestionControlLayer;

public class PeakhopperRto extends CongestionControlLayer{

	public PeakhopperRto(NetworkConfig config) {
		super(config);
	}
	
	/** This method is only called if there hasn't been an RTO update yet. It sets the weak/strong RTOs and calculates a new overall RTO.*/
	@Override
	public void initializeRTOEstimators(long measuredRTT, int estimatorType, RemoteEndpoint endpoint){
		
		endpoint.F_value = 24; // default value
		endpoint.RTT_previous = 0;
		long newRTO = (long)((1 + 0.75) * measuredRTT);		

		endpoint.updateRTO(newRTO);
	}
	
	@Override
	protected void updateEstimator(long measuredRTT, int estimatorType, RemoteEndpoint endpoint){
		
		endpoint.delta = (measuredRTT - endpoint.RTT_previous)/measuredRTT;
		endpoint.D_value = (double)(1 - 1/endpoint.F_value);
		endpoint.B_value = Math.max(endpoint.delta, endpoint.D_value*endpoint.B_value);
		endpoint.RTT_max = Math.max(measuredRTT, endpoint.RTT_previous);
		long newRTO = (long) Math.max(endpoint.D_value*endpoint.getRTO(), (1+endpoint.B_value) *endpoint.RTT_max);
		newRTO = Math.max(newRTO, endpoint.RTT_max + 2 * 50);	
		endpoint.printPeakhopperStats();
		
		endpoint.RTT_previous = measuredRTT;
			
		endpoint.updateRTO(newRTO);
	}	
	
	@Override
	public void processRTTmeasurement(long measuredRTT, Exchange exchange, int retransmissionCount){		
		
		RemoteEndpoint endpoint = getRemoteEndpoint(exchange);
		int rtoType = endpoint.getExchangeEstimatorState(exchange);
		
		if(rtoType == NOESTIMATOR || rtoType == WEAKRTOTYPE )
			return;
		
		if(endpoint.isBlindStrong() && rtoType == STRONGRTOTYPE){		
			// Received a strong RTT measurement for the first time, apply strong RTO update
			endpoint.setBlindStrong(false); 
			initializeRTOEstimators(measuredRTT, rtoType, endpoint);					
		}else{
			//Perform normal update of the RTO
			updateEstimator(measuredRTT, rtoType, endpoint);
		}
	}

}
