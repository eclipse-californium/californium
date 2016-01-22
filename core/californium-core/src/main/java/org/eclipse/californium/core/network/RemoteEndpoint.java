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
 
package org.eclipse.californium.core.network;

import java.net.InetAddress;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;

import org.eclipse.californium.core.network.config.NetworkConfig;

public class RemoteEndpoint {
	
	// The address of the remote endpoint
	private InetAddress Address;
	// The port number of the remote endpoint
	private int Port;
	// A concurrent Hash Map that contains timestamp information for the exchanges
	private ConcurrentHashMap<Exchange, exchangeInfo> exchangeInfoMap;
	
	//Overall RTO, Strong RTO, Strong RTT, Strong RTTVAR, to be used to set the retransmission timeout.
	private long[] overallRTO;
	private long[] RTOupdateTimestamp;
	
	//Current RTO stores the latest updated value
	private long currentRTO;
	
	private long meanOverallRTO;
	private long[] xRTO;
	private long[] xRTT;
	private long[] xRTTVAR;

	/* Linux algorithm variables FOR TESTING ONLY*/
	public long SRTT;
	public long RTTVAR;
	public long mdev;
	public long mdev_max;
	
	/* Peakhopper algorithm variables FOR TESTING ONLY*/
	public double delta;
	
	
	public double B_value;
	public final static double F_value = 24;
	public final static double B_max_value = 1;
	public final static double D_value = (double)(1 - (double)(1/F_value));
	public final static int RTT_HISTORY_SIZE = 2;
	public long RTT_max;
	public long[] RTT_sample = new long[2];
	public long RTT_previous;
	public long RTO_min;
	
	
	private int currentArrayElement;
	private int nonConfirmableCounter;
	
	private boolean usesBlindEstimator;
	private boolean isBlindStrong; // As long as no weak RTT measurement has been carried out, the RTO timers are calculated differently
	private boolean isBlindWeak; // As long as no weak RTT measurement has been carried out, the RTO timers are calculated differently
	
	private boolean processingNON;
	
	private final static int RTOARRAYSIZE 	= 1; 	// Amounts of elements in the RTO history length
	
	private final static int STRONGRTOTYPE = 1;
	private final static int WEAKRTOTYPE = 2;
	private final static int NOESTIMATOR = 3;
	
	/* A queue for confirmable exchanges that need to be delayed due to the NSTART limitation*/
	private Queue<Exchange> confirmableQueue; 
	
	/* A queue for non-confirmable exchanges that need to be rate-controlled */
	private Queue<Exchange> nonConfirmableQueue; 
	
	public RemoteEndpoint(int remotePort, InetAddress remoteAddress, NetworkConfig config){
		Address = remoteAddress;
		Port = remotePort;
		
		// Fill Array with initial values
		overallRTO = new long[RTOARRAYSIZE];
		for(int i=0; i < RTOARRAYSIZE; i++){
			overallRTO[i] = config.getInt(NetworkConfig.Keys.ACK_TIMEOUT) ;
		}
		currentRTO =  config.getInt(NetworkConfig.Keys.ACK_TIMEOUT);

		xRTO = new long[3];
		xRTT = new long[3];
		xRTTVAR = new long[3];
		RTOupdateTimestamp = new long[3];	
		
		for(int i=0; i <= 2; i++){
			setEstimatorValues(config.getInt(NetworkConfig.Keys.ACK_TIMEOUT), 0, 0, i);
			setRTOtimestamp(System.currentTimeMillis(), i);
		}
		meanOverallRTO = config.getInt(NetworkConfig.Keys.ACK_TIMEOUT);
		
		currentArrayElement = 0;
		nonConfirmableCounter = 7;
		
		usesBlindEstimator = true;
		isBlindStrong = true;
		isBlindWeak = true;
		
		processingNON = false;
		
		exchangeInfoMap = new ConcurrentHashMap<Exchange, exchangeInfo>();

		confirmableQueue = new LinkedList<Exchange>();
	    nonConfirmableQueue = new LinkedList<Exchange>();
	}

	public int getRemotePort(){
		return Port;
	}
	
	public InetAddress getRemoteAddress(){
		return Address;
	}
	
	public void increaseNonConfirmableCounter(){
		nonConfirmableCounter++;
	}
	
	public int getNonConfirmableCounter(){
		return nonConfirmableCounter;
	}
	
	public void resetNonConfirmableCounter(){
		nonConfirmableCounter = 0;
	}
	
	public long getRTOtimestamp(int rtoType){
		return RTOupdateTimestamp[rtoType];
	}
	
	public void setRTOtimestamp(long timestamp, int rtoType){
		RTOupdateTimestamp[rtoType] = timestamp;
	}
	
	public long getxRTO(int rtoType){
		return xRTO[rtoType];
	}
	
	public long getxRTT(int rttType){
		return xRTT[rttType];
	}
	
	public long getxRTTVAR(int rttvarType){
		return xRTTVAR[rttvarType];
	}
	
	public void useBlindEstimator(){
		usesBlindEstimator = true;
	}
	
	public boolean isBlindWeak(){
		return isBlindWeak;
	}
	
	public void setBlindWeak(boolean state){
	  isBlindWeak = state;
	}
	
	public boolean isBlindStrong(){
		return isBlindStrong;
	}
	
	public void setBlindStrong(boolean state){
		  isBlindStrong = state;
	}
	
	public void setEstimatorValues(long rto, long rtt, long rttvar, int estimatorType){
		xRTO[estimatorType] = rto;
		xRTT[estimatorType] = rtt;
		xRTTVAR[estimatorType] = rttvar;
	}	
	
	public Queue<Exchange> getConfirmableQueue(){
		return confirmableQueue;
	}
	
	public Queue<Exchange> getNonConfirmableQueue(){
		return nonConfirmableQueue;
	}
	
	public Exchange pollConfirmableExchange(){
		return confirmableQueue.poll();
	}
	
	private void calculateMeanOverallRTO(){
		long meanRTO = 0;
		int i;
		for(i=0; i < RTOARRAYSIZE; i++)
			meanRTO += overallRTO[i];
		
		meanOverallRTO = meanRTO/RTOARRAYSIZE;		
	}
	
	public void setCurrentRTO(long currentRTO){
		this.currentRTO = currentRTO;
	}
	
	public long getCurrentRTO(){
		return currentRTO;
	}
	
	// Once a valid measurement is received, the currentRTO needs to be the same as the last updated overall RTO
	public void matchCurrentRTO(){
		currentRTO = meanOverallRTO;
	}
	public void setProcessingNON(boolean value){
		processingNON = value;
	}
	
	public boolean getProcessingNON(){
		return processingNON;
	}
	
	/**
	 * Obtains either blind RTO value for the next transmission (if no RTT measurements have been done so far) or gets the overall RTO (CoCoA)
	 * @return the RTO in milliseconds
	 */
	public long getRTO() {
		long rto;
		if (usesBlindEstimator && isBlindStrong && isBlindWeak && exchangeInfoMap.size() > 1) {
			// No RTT measurements have been possible so far => apply blind
			// estimator rule
			// System.out.println("Blind Rule applying, RTO: "+(exchangeInfoMap.size())*2000);
			rto = (long) (exchangeInfoMap.size()) * 2000;
		} else {
			if (meanOverallRTO != currentRTO) {
				// If current RTO was not updated, there was no successful RTO
				// update, use the one that has backed offs
				// System.out.println("Old RTO! (mean/current) = (" +meanOverallRTO+ "/" + currentRTO +")");
				rto = currentRTO;
			} else {
				rto = meanOverallRTO;
			}
		}
		return (rto < 32000) ? rto : 32000;
	}
	
	/**
	 * Very small RTOs are "boosted" if they are not updated. In the current configuration this
	 * is achieved by doubling the current overall RTO.
	 */
	public void boostRTOvalue(){
		meanOverallRTO *= 2;
	}
	
	/**
	 * Very large RTOs are "reduced" if they are not updated. In the current configuration this
	 * is achieved by doubling the current overall RTO.
	 */
	public void reduceRTOvalue(){
		meanOverallRTO = (long) (1000 + (0.5 * meanOverallRTO));
	}
	
	
	/**
	 * Update stored RTO value.
	 * @param newRTO the new RTO value
	 */
	public void updateRTO(long newRTO){
		overallRTO[currentArrayElement] = newRTO; 		
		currentArrayElement = (currentArrayElement + 1)%RTOARRAYSIZE;
		calculateMeanOverallRTO();
		setCurrentRTO(newRTO);
	}
	
	/**
	 * This method allows to set the state of the exchange (WEAK/STRONG/notvalid RTT measurement).
	 * @param exchange the exchange
	 */
	public void setEstimatorState(Exchange exchange){
		//When no CC layer is used, the entries are all null, check here if this is the case
		if(exchangeInfoMap.get(exchange) == null){
			return;
		}
		
		/*if(exchange.getFailedTransmissionCount() == 5){
			//TODO: If all retransmissions expired, do delete exchange (use config file to get this value "5" or use another method to delete exchange?)
				removeExchangeInfo(exchange);
				return;
		}*/
		if(exchange.getFailedTransmissionCount() == 1 || exchange.getFailedTransmissionCount() == 2){
			//Only allow weak estimator updates from the first or second retransmission
			//System.out.println("Remote Enpdoint: WEAK");
			exchangeInfoMap.get(exchange).setTypeWeakEstimator();
		}else{
			//If more than 1 retransmission was applied to the exchange, mark this entry as not updatable
			//System.out.println("Remote Enpdoint: NO");
			exchangeInfoMap.get(exchange).setTypeNoEstimator();
		}
	}
	
	/**
	 * Confirmable exchanges are registered at the remote endpoint 
	 * @param exchange the exchange to register
	 * @param vbf the variable back-off factor
	 */
	public void registerExchange(Exchange exchange, double vbf){
		exchangeInfo newExchange = new exchangeInfo(System.currentTimeMillis(), vbf);
		exchangeInfoMap.put(exchange, newExchange);
	}
	
	/**
	 * Get timestamp of transmission of the message
	 * @param exchange the exchange
	 * @return the timestamp in 
	 */
	public long getExchangeTimestamp(Exchange exchange){	
		long storedTimestamp = 0;	
		if(exchangeInfoMap.isEmpty()){
			return 0;
		}
		
		if(exchangeInfoMap.get(exchange) != null){
			storedTimestamp = exchangeInfoMap.get(exchange).getTimestamp();
		}
		return storedTimestamp;
	}
	
	/**
	 * Returns the variable back-off factor for this exchange.
	 * @param exchange the exchange
	 * @return the VBF
	 */
	public double getExchangeVBF(Exchange exchange){	
		double vbf = 2;	
		if(exchangeInfoMap.isEmpty()){
			return 0;
		}
		
		if(exchangeInfoMap.get(exchange) != null){
			vbf = exchangeInfoMap.get(exchange).getVBF();
		}
		return vbf;
	}
	
	/**
	 * Gets state (Strong/Weak/NoValidRTT) for this exchange
	 * @param exchange the exchange
	 * @return the estimator ID
	 */
	public int getExchangeEstimatorState(Exchange exchange){	
		if(exchangeInfoMap.isEmpty()){
			//System.out.println("No exchanges stored (estimator state request)");
		}
		
		if(exchangeInfoMap.get(exchange) != null){
			return exchangeInfoMap.get(exchange).getEstimatorType();
		}
		return 0;
	}
	/**
	 * Removes all information of a finished exchange
	 * @param exchange the exchange to remove
	 * @return true if removed
	 */
	public boolean removeExchangeInfo(Exchange exchange){
		if(exchangeInfoMap.remove(exchange) == null){
			return false;
		}else{
		//deleted exchange!
		return true;
		}
	}
	
	/**
	 * Checks if an exchange in the list was was deleted
	 */
	public void checkForDeletedExchanges(){
		//System.out.println("Checking for old exchanges in remote Endpoints.");
	    for (Object o : exchangeInfoMap.entrySet()){
	    	if(o == null){
	    		//System.out.println("Deleting old entry (null-entry).");
	    		exchangeInfoMap.remove(o);
	    	}
	    }
	}
	
	/**
	 * Gets amount of currently active exchanges
	 * @param exchange the exchange
	 * @return the count
	 */
	public int getNumberOfOngoingExchanges(Exchange exchange){	
		//System.out.println("Amount of exchanges: " + exchangeInfoMap.size() );
		return exchangeInfoMap.size();
	}
	
	public void printLinuxStats(){
		System.out.println("SRTT: " + SRTT + " RTTVAR: " + RTTVAR + " mdev: " + mdev + " mdev_max: " + mdev_max);
	}
	
	public void printPeakhopperStats(){
	    System.out.println("Delta: " + delta + " D: " + D_value + " B: " + B_value + " RTT_max: " + RTT_max);
	}
	
	/**
	 * Object that stores exchange related information 
	 * 1.) Timestamp
	 * 2.) Variable Backoff Factor
	 * 3.) Estimator Type (weak/strong/none)
	 */ 
	private class exchangeInfo{
		
		private long timestamp;
		private double vbf;
		private int estimatorType;
		
		public exchangeInfo(long timestamp, double vbf){
			this.timestamp = timestamp;
			this.vbf = vbf;
			estimatorType = STRONGRTOTYPE;
			//System.out.println("Exchange stored in remote Endpoint (" + System.currentTimeMillis() + ")");
		}
		
		public void setTypeWeakEstimator(){
			estimatorType = WEAKRTOTYPE;
		}
		public void setTypeNoEstimator(){
			estimatorType = NOESTIMATOR;
		}
		public int getEstimatorType(){
			return estimatorType;
		}
		
		public long getTimestamp(){
			return timestamp;
		}
		
		public double getVBF(){
			return vbf;
		}
	}
}
