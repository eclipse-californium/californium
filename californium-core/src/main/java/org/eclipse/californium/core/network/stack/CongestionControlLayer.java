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
 *    Achim Kraus (Bosch Software Innovations GmbH) - change lower()/upper() back to super
 *                                                    to ensure, that ReliabilityLayer
 *                                                    is processed.
 ******************************************************************************/
 
package org.eclipse.californium.core.network.stack;

import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.RemoteEndpoint;
import org.eclipse.californium.core.network.RemoteEndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.stack.congestioncontrol.*;

/**
 * The optional Congestion Control (CC) Layer for the Californium CoAP implementation provides the methods for advanced congestion 
 * control mechanisms. The RTO calculations and other mechanisms are implemented in the correspondent child classes. 
 * The alternatives to CoCoA are implemented for testing purposes and are not maintained/updated.  
 * 
 * BASICRTO = Use previously measured RTT and multiply it by 1.5 to calculate the RTO for the next transmission
 * COCOA = CoCoA algorithm as defined in draft-bormann-cocoa-02
 * LINUXRTO = The Linux RTO calculation mechanism
 * COCOASTRONG = CoCoA but only with the strong estimator
 * PEAKHOPPERRTO  = The Peakhopper RTO calculation mechanism (PH-RTO)
 * 
 * @author augustbetzler
 *
 */

public abstract class CongestionControlLayer extends ReliabilityLayer {

	/** The configuration */ 
	protected NetworkConfig config;

	private final static long MAX_REMOTE_TRANSACTION_DURATION = 255 * 1000; // Maximum duration of a transaction, after that, sweep the exchanges
	// Amount of non-confirmables that can be transmitted before a NON is converted to a CON (to get an RTT measurement); this is a CoCoA feature
	private final static int MAX_SUCCESSIVE_NONS = 7; 

	protected final static int OVERALLRTOTYPE = 0;
	protected final static int STRONGRTOTYPE = 1;
	protected final static int WEAKRTOTYPE = 2;
	protected final static int NOESTIMATOR = 3;

	private final static int EXCHANGELIMIT = 50; // An upper limit for the queue size of confirmables and non-confirmables (separate queues)

	private final static int MAX_RTO = 60000;

	private boolean appliesDithering; // In CoAP, dithering is applied to the initial RTO of a transmission; set to true to apply dithering

	private RemoteEndpointManager remoteEndpointmanager;

	/**
	 * Constructs a new congestion control layer.
	 * 
	 * @param config the configuration
	 */
	public CongestionControlLayer(final NetworkConfig config) {
		super(config);
		this.config = config;
		this.remoteEndpointmanager = new RemoteEndpointManager(config);
		setDithering(false);
	}

	protected RemoteEndpoint getRemoteEndpoint(final Exchange exchange){
		return remoteEndpointmanager.getRemoteEndpoint(exchange);
	}

	public boolean appliesDithering(){
		return appliesDithering;
	}

	public void setDithering(boolean mode){
		this.appliesDithering = mode;
	}

	/*
	 * Calculate how long the maximum transmission duration will be when no ACK is received
	 */
	//FIXME What was this good for? Result unused in prepareRetransmission().
//	private int calculateMaxTransactionDuration(Exchange exchange){
//		return (int)(config.getInt(NetworkConfigDefaults.ACK_TIMEOUT_SCALE)*getRemoteEndpoint(exchange).getRTO()* Math.pow(getRemoteEndpoint(exchange).getExchangeVBF(exchange), 5));
//	}
	
	/*
	 * Method called when receiving a Response/Request from the upper layers: 
	 * 1.) Checks first whether a Response or Request is processed (to obtain the NON/CON Type)
	 * 2.) Checks if message is a non-confirmable. If so, it is added to the non-confirmable queue and in case 
	 * 	   the bucket thread is not running, it is started
	 * 3.) Checks if message is confirmable and if the NSTART rule is followed. If more than NSTART exchanges are running, the Request is enqueued.
	 *     If the NSTART limit is respected, the message is passed on to the reliability layer.
	 */
	private boolean processMessage(final Exchange exchange, final Message message) {
		Type messageType = message.getType();

		// Put into queues for NON or CON messages
		if (messageType == Type.CON) {
			if (!checkNSTART(exchange)) { // Check if NSTART is not reached yet
										  // for confirmable transmissions
				return false;
			}
		} else if (getRemoteEndpoint(exchange).getNonConfirmableCounter() > MAX_SUCCESSIVE_NONS) {
			// Every MAX_SUCCESSIVE_NONS + 1 packets, a non-confirmable needs to
			// be converted to a confirmable [CoCoA]
			if (exchange.getCurrentRequest().getDestinationPort() != 0) {
				exchange.getCurrentRequest().setType(Type.CON);
			} else if (exchange.getCurrentResponse() != null) {
				exchange.getCurrentResponse().setType(Type.CON);
			}
			getRemoteEndpoint(exchange).resetNonConfirmableCounter();

			// Check if NSTART is not reached yet for confirmable transmissions
			if (!checkNSTART(exchange)) {
				return false;
			}
		} else {
			// Check of if there's space to queue a NON
			if (getRemoteEndpoint(exchange).getNonConfirmableQueue().size() == EXCHANGELIMIT) {
				// System.out.println("Non-confirmable exchange queue limit reached!");
				// TODO: Drop packet -> Notify upper layers?
			} else {
				getRemoteEndpoint(exchange).getNonConfirmableQueue().add(
						exchange);

				// Check if NONs are already processed, if not, start bucket
				// Thread
				if (!getRemoteEndpoint(exchange).getProcessingNON()) {
					executor.schedule(new BucketThread(
							getRemoteEndpoint(exchange)), 0,
							TimeUnit.MILLISECONDS);
				}
			}
			return false;
		}
		return true;

	}

	/*
	 * Check if the limit of exchanges towards the remote endpoint has reached NSTART.
	 */
	private boolean checkNSTART(final Exchange exchange) {
		getRemoteEndpoint(exchange).checkForDeletedExchanges();
		if (getRemoteEndpoint(exchange).getNumberOfOngoingExchanges(exchange) < config
				.getInt("NSTART")) {
			// System.out.println("Processing exchange (NSTART OK!)");

			// NSTART allows to start the exchange, proceed normally
			getRemoteEndpoint(exchange).registerExchange(exchange,
					calculateVBF(getRemoteEndpoint(exchange).getRTO()));

			// The exchange needs to be deleted after at least 255 s TODO:
			// should this value be calculated dynamically
			executor.schedule(new SweepCheckTask(getRemoteEndpoint(exchange),
					exchange), MAX_REMOTE_TRANSACTION_DURATION,
					TimeUnit.MILLISECONDS);
			return true;
		} else {
			// NSTART does not allow any further parallel exchanges towards the
			// remote endpoint
			// System.out.println("Nstart does not allow further exchanges with "
			// + getRemoteEndpoint(exchange).getRemoteAddress().toString());

			// Check if the queue limit for exchanges is already reached
			if (getRemoteEndpoint(exchange).getConfirmableQueue().size() == EXCHANGELIMIT) {
				// Request cannot be queued TODO: does this trigger some
				// feedback for other layers?
				// System.out.println("Confirmable exchange queue limit reached! Message dropped...");

			} else {
				// Queue exchange in the CON-Queue
				getRemoteEndpoint(exchange).getConfirmableQueue().add(exchange);
				// System.out.println("Added exchange to the queue (NSTART limit reached)");
			}
		}
		return false;
	}

	/*
	 * When a response or an ACK was received, update the RTO values with the measured RTT.
	 */
	private void calculateRTT(final Exchange exchange){	
		long timestamp, measuredRTT;
		timestamp = getRemoteEndpoint(exchange).getExchangeTimestamp(exchange);
		if (timestamp != 0){
			measuredRTT = System.currentTimeMillis() - timestamp;
			// process the RTT measurement
			processRTTmeasurement(measuredRTT, exchange, exchange.getFailedTransmissionCount());
			getRemoteEndpoint(exchange).removeExchangeInfo(exchange);
		}
	}

	/** 
	 * Received a new RTT measurement, evaluate it and update correspondent estimators 
	 * 
	 * @param measuredRTT			the round-trip time of a CON-ACK pair
	 * @param exchange				the exchange that was used for the RTT measurement
	 * @param retransmissionCount	the number of retransmissions that were applied to the transmission of the CON message
	 */
	protected void processRTTmeasurement(final long measuredRTT, final Exchange exchange, final int retransmissionCount){		
		//Default CoAP does not use RTT info, so do nothing
		return;
	}

	/**
	 * Override this method in RTO algorithms that implement some sort of RTO aging
	 * @param exchange the exchange
	 */
	protected void checkAging(final Exchange exchange) {
		return;
	}

	/**
	 * This method is only called if there hasn't been an RTO update yet. 
	 * 
	 * @param measuredRTT   the time it took to get an ACK for a CON message
	 * @param estimatorType the type indicating if the measurement was a strong or a weak one
	 * @param endpoint      the Remote Endpoint for which the RTO update is done
	 */
	protected void initializeRTOEstimators(final long measuredRTT, final int estimatorType, final RemoteEndpoint endpoint){		
		long newRTO = config.getInt(NetworkConfig.Keys.ACK_TIMEOUT);

		endpoint.updateRTO(newRTO);
	}

	/**
	 * If the RTO estimator already has been used previously, this function takes care of updating it according to the
	 * new RTT measurement (or other trigger for non-CoCoA algorithms)
	 * 
	 * @param measuredRTT   Time it took to get an ACK for a CON message
	 * @param estimatorType Estimatortype indicates if the measurement was a strong or a weak one
	 * @param endpoint      The Remote Endpoint for which the RTO update is done
	 */
	protected void updateEstimator(final long measuredRTT, final int estimatorType, final RemoteEndpoint endpoint){
		// Default CoAP always uses the default timeout
		long newRTO = config.getInt(NetworkConfig.Keys.ACK_TIMEOUT);
		endpoint.updateRTO(newRTO);
	}	

	/**
	 * Calculates the Backoff Factor for the retransmissions. By default this is a binary backoff (= 2)
	 * 
	 * @param rto the initial RTO value
	 * @return the new VBF
	 */
	protected double calculateVBF(final long rto){
		return config.getFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE);
	}

	/*
	 * Gets a request or response from the dedicated queue and polls it
	 */
	private void checkRemoteEndpointQueue(final Exchange exchange) {
		// 0 = empty queue | 1 = response | 2 = request
		if (!getRemoteEndpoint(exchange).getConfirmableQueue().isEmpty()) {
			// We have some exchanges that need to be processed; is it a
			// response or a request?
			Exchange queuedExchange = getRemoteEndpoint(exchange).getConfirmableQueue().poll();
			if (queuedExchange.getCurrentResponse() != null) {
				// it's a response
				sendResponse(queuedExchange, queuedExchange.getCurrentResponse());
			} else if (queuedExchange.getCurrentRequest() != null) {
				// it's a request
				sendRequest(queuedExchange, queuedExchange.getCurrentRequest());
			}
		}
	}

	/**
	 * Forward the request to the lower layer.
	 * @param exchange the exchange
	 * @param request the current request
	 */
	@Override
	public void sendRequest(final Exchange exchange, final Request request) {
		// Check if exchange is already running into a retransmission; if so, don't call processMessage
		if (exchange.getFailedTransmissionCount() > 0) {
			// process ReliabilityLayer
			super.sendRequest(exchange, request);
		} else if (processMessage(exchange, request)) {
			checkAging(exchange);
			// process ReliabilityLayer
			super.sendRequest(exchange, request);
		}
	}

	/**
	 * Forward the response to the lower layer.
	 * @param exchange the exchange
	 * @param response the current response
	 */
	@Override
	public void sendResponse(final Exchange exchange, final Response response) {
		// Check if exchange is already running into a retransmission; if so, don't call processMessage, since this is a retransmission
		if (exchange.getFailedTransmissionCount() > 0) {
			// process ReliabilityLayer
			super.sendResponse(exchange, response);
		} else if (processMessage(exchange, response)) {
			checkAging(exchange);
			super.sendResponse(exchange, response);
		}
	}

	/**
	 * The following method overrides the method provided by the reliability layer to include the advanced RTO calculation values
	 * when determining the RTO.
	 */
	@Override
	protected void prepareRetransmission(final Exchange exchange, final RetransmissionTask task) {
		int timeout;
		//System.out.println("TXCount: " + exchange.getFailedTransmissionCount());
		if (exchange.getFailedTransmissionCount() == 0) {
			timeout = (int)getRemoteEndpoint(exchange).getRTO();	
			if(appliesDithering()){
				//TODO: Workaround to force CoCoA (-Strong) not to use the same RTO after backing off several times
				//System.out.println("Applying dithering, matching RTO");
				getRemoteEndpoint(exchange).matchCurrentRTO();
				timeout = (int)getRemoteEndpoint(exchange).getRTO();
				// Apply dithering by randomly choosing RTO from [RTO, RTO * 1.5]
				float ack_random_factor = config.getFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR);
				timeout = getRandomTimeout(timeout, (int) (timeout*ack_random_factor));
			}
			//System.out.println("meanrto:" + timeout + ";" + System.currentTimeMillis());
		} else {
				int tempTimeout= (int)(getRemoteEndpoint(exchange).getExchangeVBF(exchange) * exchange.getCurrentTimeout());
				timeout = (tempTimeout < MAX_RTO) ? tempTimeout : MAX_RTO;
				getRemoteEndpoint(exchange).setCurrentRTO(timeout);
				//System.out.println("RTX");
		}
		exchange.setCurrentTimeout(timeout);
		//expectedmaxduration = calculateMaxTransactionDuration(exchange); //FIXME what was this for?
		//System.out.println("Sending MSG (timeout;timestamp:" + timeout + ";" + System.currentTimeMillis() + ")");
		ScheduledFuture<?> f = executor.schedule(task , timeout, TimeUnit.MILLISECONDS);
		exchange.setRetransmissionHandle(f);	
	}

	@Override
	public void receiveResponse(final Exchange exchange, final Response response) {
		//August: change the state of the remote endpoint (STRONG/WEAK/NOESTIMATOR) if failedTransmissionCount = 0;
		if (exchange.getFailedTransmissionCount() != 0) {
			getRemoteEndpoint(exchange).setEstimatorState(exchange);
		}
		super.receiveResponse(exchange, response);
		
		calculateRTT(exchange);	
		checkRemoteEndpointQueue(exchange);	
	}

	/**
	 * If we receive an ACK or RST, calculate the RTT and update the RTO values
	 */
	@Override
	public void receiveEmptyMessage(final Exchange exchange, final EmptyMessage message) {
		// If retransmissions were used, update the estimator state (WEAK / NO)
		if (exchange.getFailedTransmissionCount() != 0) {
			getRemoteEndpoint(exchange).setEstimatorState(exchange);
		}
		super.receiveEmptyMessage(exchange, message);
		
		calculateRTT(exchange);
		checkRemoteEndpointQueue(exchange);
	}	

	/**
	 * Method to send NON packets chosen by the bucket Thread (no reliability)
	 * 
	 * @param exchange the exchange
	 * @param request the request
	 */
	public void sendBucketRequest(final Exchange exchange, final Request request) {
		super.sendRequest(exchange, request);
	}

	/**
	 * Method to send NON packets chosen by the bucket Thread (no reliability)
	 * 
	 * @param exchange the exchange
	 * @param response the response
	 */
	public void sendBucketResponse(final Exchange exchange, final Response response) {
		super.sendResponse(exchange, response);
	}

	/*
	 * This Thread is used to apply rate control to non-confirmables by polling them from the queue and
	 * scheduling the task to run again later.
	 */
	private class BucketThread implements Runnable {

		RemoteEndpoint endpoint;

		public BucketThread(final RemoteEndpoint queue) {
			endpoint = queue;
		}

		@Override
		public void run() {
			if (!endpoint.getNonConfirmableQueue().isEmpty()) {
				endpoint.setProcessingNON(true);

				Exchange exchange = endpoint.getNonConfirmableQueue().poll();

				if (getRemoteEndpoint(exchange).getNonConfirmableCounter() <= MAX_SUCCESSIVE_NONS) {
					getRemoteEndpoint(exchange).increaseNonConfirmableCounter();
					if (exchange.getCurrentRequest().getDestinationPort() != 0) {
						// it's a response
						sendBucketRequest(exchange, exchange.getCurrentRequest());
					} else if (exchange.getCurrentResponse() != null) {
						// it's a request
						sendBucketResponse(exchange, exchange.getCurrentResponse());
					}
				}
				// schedule next transmission of a NON based on the RTO value (rate = 1/RTO)
				executor.schedule(
						new BucketThread(getRemoteEndpoint(exchange)),
						getRemoteEndpoint(exchange).getRTO(),
						TimeUnit.MILLISECONDS);

			} else {
				endpoint.setProcessingNON(false);
			}
		}
	}

	/*
	 * Task that deletes old exchanges from the remote endpoint list
	 */
	private class SweepCheckTask implements Runnable {
		
		final RemoteEndpoint endpoint;
		final Exchange exchange;

		public SweepCheckTask(final RemoteEndpoint endpoint, final Exchange exchange) {
			this.endpoint = endpoint;
			this.exchange = exchange;
		}

		@Override
		public void run() {
			if (endpoint.removeExchangeInfo(exchange) == false) {
				// The entry already was removed
			} else {
				// Entry was removed, check if there are more messages in the
				// queue
				checkRemoteEndpointQueue(exchange);
			}
		}
	}

	public static CongestionControlLayer newImplementation(final NetworkConfig config) {

		final String implementation = config.getString(NetworkConfig.Keys.CONGESTION_CONTROL_ALGORITHM, "Cocoa");
		switch(implementation) {
		case "Cocoa":
			return new Cocoa(config);
		case "CocoaStrong":
			return new CocoaStrong(config);
		case "BasicRto":
			return new BasicRto(config);
		case "LinuxRto":
			return new LinuxRto(config);
		case "PeakhopperRto":
			return new PeakhopperRto(config);
		default:
			LOGGER.log(
				Level.CONFIG,
				"configuration contains unsupported {0}, using Cocoa",
				NetworkConfig.Keys.CONGESTION_CONTROL_ALGORITHM);
			return new Cocoa(config);
		}
	}
}
