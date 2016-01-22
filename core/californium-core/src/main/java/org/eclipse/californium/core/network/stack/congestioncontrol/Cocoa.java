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


public class Cocoa extends CongestionControlLayer {
	
	private final static int KSTRONG		= 4;
	private final static int KWEAK			= 1;
	private final static double ALPHA  	 	= 0.25;
	private final static double BETA 		= 0.125;
	
	private final static double STRONGWEIGHTING = 0.5;
	private final static double WEAKWEIGHTING = 0.25;
	
	private int[] kValue = {KSTRONG, KWEAK};
	private double[] weighting = {STRONGWEIGHTING, WEAKWEIGHTING};
	
	private final static long LOWERVBFLIMIT = 1000; // determines the threshold for RTOs to be considered "small"
	private final static long UPPERVBFLIMIT = 3000; // determines the threshold for RTOs to be considered "large"
	private final static double VBFLOW 		= 3;
	private final static double VBFHIGH		= 1.5;
	
	//Not used for the current version of CoCoA
	//private final static long UPPERAGELIMIT	= 30000; // determines after how long (ms) an estimator undergoes the aging process
	
	public Cocoa(NetworkConfig config) {
		super(config);
		setDithering(true);
	}

	
	/** This method is only called if there hasn't been an RTO update yet. It sets the weak/strong RTOs and calculates a new overall RTO.*/
	@Override
	public void initializeRTOEstimators(long measuredRTT, int estimatorType, RemoteEndpoint endpoint) {
				
		long RTT = measuredRTT;
		long RTTVAR = measuredRTT/2;
		long RTO = RTT + kValue[estimatorType-1]*RTTVAR;
		long newRTO = Math.round((double)RTO*(weighting[estimatorType-1]) + Math.round((double)(endpoint.getRTO()*(1-weighting[estimatorType-1]))));		
		endpoint.setEstimatorValues(RTO, RTT, RTTVAR, estimatorType);
		endpoint.setRTOtimestamp(System.currentTimeMillis(), estimatorType);
		endpoint.setRTOtimestamp(System.currentTimeMillis(), OVERALLRTOTYPE);
		
		//System.out.println("RTO:" + RTO + " RTT:" + RTT + " RTTVAR:" + RTTVAR + " (Type:" + estimatorType + ")");

		//long newRTO = Math.round((double)meanOverallRTO*0.5) + Math.round((double)(getxRTO(estimatorType)*0.5));

		endpoint.updateRTO(newRTO);
	}

	@Override
	protected void updateEstimator(long measuredRTT, int estimatorType, RemoteEndpoint endpoint) {
		
		long RTTVAR = Math.round((double)(1-BETA)*endpoint.getxRTTVAR(estimatorType)) + Math.round((double)(BETA*Math.abs(endpoint.getxRTT(estimatorType)-measuredRTT)));
		long RTT =  Math.round((double)(endpoint.getxRTT(estimatorType)*(1-ALPHA))) + Math.round((double)(measuredRTT*ALPHA));
		long RTO = RTT + kValue[estimatorType-1]*RTTVAR;	
		long newRTO = Math.round((double)RTO*(weighting[estimatorType-1]) + Math.round((double)(endpoint.getRTO()*(1-weighting[estimatorType-1]))));
		endpoint.setEstimatorValues(RTO, RTT, RTTVAR, estimatorType);
		endpoint.setRTOtimestamp(System.currentTimeMillis(), estimatorType);
		endpoint.setRTOtimestamp(System.currentTimeMillis(), OVERALLRTOTYPE);

		//System.out.println("RTO:" + RTO + " RTT:" + RTT + " RTTVAR:" + RTTVAR + " (Type:" + estimatorType + ")");

		endpoint.updateRTO(newRTO);
	}	
	
	@Override
	public void processRTTmeasurement(long measuredRTT, Exchange exchange, int retransmissionCount) {		
		//System.out.println("Measured an RTT of " + measuredRTT + " after using " + retransmissionCount + " retries." );	
		RemoteEndpoint endpoint = getRemoteEndpoint(exchange);
		int rtoType = endpoint.getExchangeEstimatorState(exchange);
	
		if(rtoType == NOESTIMATOR)
			return;

		endpoint.matchCurrentRTO();
	
		//System.out.println("Measured RTT:" + measuredRTT);
		
		// System.out.println("Endpoint status: blindweak/blindstrong/state : " + endpoint.isBlindWeak() + "/" + endpoint.isBlindStrong() + "/" + endpoint.getExchangeEstimatorState(exchange));
		if (endpoint.isBlindWeak() && rtoType == WEAKRTOTYPE) {
			// Received a weak RTT for the first time, apply weak RTO update
			endpoint.setBlindWeak(false);
			initializeRTOEstimators(measuredRTT, WEAKRTOTYPE, endpoint);
		} else if (endpoint.isBlindStrong() && rtoType == STRONGRTOTYPE) {
			// Received a strong RTT measurement for the first time, apply strong RTO update
			endpoint.setBlindStrong(false);
			initializeRTOEstimators(measuredRTT, STRONGRTOTYPE, endpoint);
		} else {
			// Perform normal update of the RTO
			updateEstimator(measuredRTT, rtoType, endpoint);
		}	
	}
	
	/**
	 * CoCoA applies a variable backoff factor (VBF) to retransmissions, depending on the RTO value of the first transmission
	 * of the CoAP request.
	 * @param rto the initial RTO
	 * @return the new VBF
	 */
	public double calculateVBF(long rto) {
		if (rto > UPPERVBFLIMIT) {
			return VBFHIGH;
		}
		if (rto < LOWERVBFLIMIT) {
			return VBFLOW;
		}
		return config.getFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE);
	}
	
	/**
	 *  Aging check: 
	 *  1.) If the overall estimator has a value below 1 s and 16*RTO seconds pass without an update, double the value of the RTO (apply cumulatively!)
	 *  2.) If the overall estimator has a value above 3 s and 4*RTO seconds pass without an update, reduce its value
	 */	
	@Override
	public void checkAging(Exchange exchange){
		long overallDifference = System.currentTimeMillis() - getRemoteEndpoint(exchange).getRTOtimestamp(OVERALLRTOTYPE);
		
		// Increase mean overall RTO if condition 1) is true
		while(true){
			if(overallDifference > (16*getRemoteEndpoint(exchange).getRTO()) && getRemoteEndpoint(exchange).getRTO() < LOWERVBFLIMIT){
				//System.out.println("RTO before:" + exchange.getRemoteEndpoint().getRTO());
				overallDifference -= (16*getRemoteEndpoint(exchange).getRTO());
				getRemoteEndpoint(exchange).boostRTOvalue();
				getRemoteEndpoint(exchange).setRTOtimestamp(System.currentTimeMillis(), OVERALLRTOTYPE);
				//System.out.println("Boosted RTO:" + getRemoteEndpoint(exchange).getRTO());			
			}else{
				break;
			}
		}
		// Decrease mean overall RTO of an endpoint if condition 2) is true
		while(true){
			if(overallDifference > (4*getRemoteEndpoint(exchange).getRTO()) && getRemoteEndpoint(exchange).getRTO() > UPPERVBFLIMIT){
				//System.out.println("RTO before:" + exchange.getRemoteEndpoint().getRTO());
				overallDifference -= (4*getRemoteEndpoint(exchange).getRTO());
				getRemoteEndpoint(exchange).reduceRTOvalue();
				getRemoteEndpoint(exchange).setRTOtimestamp(System.currentTimeMillis(), OVERALLRTOTYPE);
				//System.out.println("Decayed RTO:" + getRemoteEndpoint(exchange).getRTO());			
			}else{
				break;
			}
		}
		
		/* TODO: This part may be included in future Versions of CoCoAs
		//long strongDifference = System.currentTimeMillis() - getRemoteEndpoint(exchange).getRTOtimestamp(STRONGRTOTYPE);
		//long weakDifference = System.currentTimeMillis() - getRemoteEndpoint(exchange).getRTOtimestamp(WEAKRTOTYPE);
		// Apply aging to to the strong estimator (RTT) if condition 2) is true
		while(true){
			if(strongDifference > UPPERAGELIMIT && exchange.getRemoteEndpoint().getxRTT(STRONGRTOTYPE) > config.getInt(NetworkConfigDefaults.ACK_TIMEOUT)	){
				strongDifference -= UPPERAGELIMIT;
				exchange.getRemoteEndpoint().setEstimatorValues(exchange.getRemoteEndpoint().getRTO(), (exchange.getRemoteEndpoint().getxRTT(STRONGRTOTYPE) + config.getInt(NetworkConfigDefaults.ACK_TIMEOUT)	)/2, exchange.getRemoteEndpoint().getxRTTVAR(STRONGRTOTYPE)/2, STRONGRTOTYPE);
				//strongRTTVAR  = strongRTTVAR/2;
				exchange.getRemoteEndpoint().setRTOtimestamp(System.currentTimeMillis(), STRONGRTOTYPE);
				System.out.println("Aging: Reducing Strong RTT!");
			}else{
				break;
			}
		}
		// Apply aging to to the weak estimator (RTT) if condition 2) is true
		while(true){
			if(weakDifference > UPPERAGELIMIT && exchange.getRemoteEndpoint().getxRTT(WEAKRTOTYPE) > config.getInt(NetworkConfigDefaults.ACK_TIMEOUT)){
				weakDifference -= UPPERAGELIMIT;
				exchange.getRemoteEndpoint().setEstimatorValues(exchange.getRemoteEndpoint().getRTO(), (exchange.getRemoteEndpoint().getxRTT(WEAKRTOTYPE) + config.getInt(NetworkConfigDefaults.ACK_TIMEOUT))/2, exchange.getRemoteEndpoint().getxRTTVAR(WEAKRTOTYPE)/2, WEAKRTOTYPE);
				//strongRTTVAR  = strongRTTVAR/2;
				exchange.getRemoteEndpoint().setRTOtimestamp(System.currentTimeMillis(), WEAKRTOTYPE);
				System.out.println("Aging: Reducing Weak RTT!");
			}else{
				break;
			}
		}

		*/
	}
}
