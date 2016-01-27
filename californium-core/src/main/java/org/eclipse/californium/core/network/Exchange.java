/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.util.Arrays;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.stack.BlockwiseLayer;
import org.eclipse.californium.core.network.stack.BlockwiseStatus;
import org.eclipse.californium.core.network.stack.CoapStack;
import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.core.server.resources.CoapExchange;

/**
 * An exchange represents the complete state of an exchange of one request and
 * one or more responses. The lifecycle of an exchange ends when either the last
 * response has arrived and is acknowledged, when a request or response has been
 * rejected from the remote endpoint, when the request has been canceled, or when
 * a request or response timed out, i.e., has reached the retransmission
 * limit without being acknowledged.
 * <p>
 * The framework internally uses the class Exchange to manage an exchange
 * of {@link Request}s and {@link Response}s. The Exchange only contains state,
 * no functionality. The CoAP Stack contains the functionality of the CoAP
 * protocol and modifies the exchange appropriately. The class Exchange and its
 * fields are <em>NOT</em> thread-safe.
 * <p>
 * The class {@link CoapExchange} provides the corresponding API for developers.
 * Proceed with caution when using this class directly, e.g., through
 * {@link CoapExchange#advanced()}.
 * <p>
 * This class might change with the implementation of CoAP extensions.
 */
public class Exchange {
	
	private static final AtomicInteger INSTANCE_COUNTER = new AtomicInteger();
	
	/**
	 * The origin of an exchange. If Cf receives a new request and creates a new
	 * exchange the origin is REMOTE since the request has been initiated from a
	 * remote endpoint. If Cf creates a new request and sends it, the origin is
	 * LOCAL.
	 */
	public enum Origin {
		LOCAL, REMOTE;
	}

	/** The endpoint that processes this exchange */
	private Endpoint endpoint;
	
	/** An observer to be called when a request is complete */
	private ExchangeObserver observer;
	
	/** Indicates if the exchange is complete */
	private boolean complete = false;
	
	/** The timestamp when this exchange has been created */
	private final long timestamp;
	
	/**
	 * The actual request that caused this exchange. Layers below the
	 * {@link BlockwiseLayer} should only work with the {@link #currentRequest}
	 * while layers above should work with the {@link #request}.
	 */
	private Request request; // the initial request we have to exchange
	
	/**
	 * The current block of the request that is being processed. This is a single
	 * block in case of a blockwise transfer or the same as {@link #request} in
	 * case of a normal transfer.
	 */
	private Request currentRequest; // Matching needs to know for what we expect a response
	
	/** The status of the blockwise transfer. null in case of a normal transfer */
	private BlockwiseStatus requestBlockStatus;
	
	/**
	 * The actual response that is supposed to be sent to the client. Layers
	 * below the {@link BlockwiseLayer} should only work with the
	 * {@link #currentResponse} while layers above should work with the
	 * {@link #response}.
	 */
	private Response response;
	
	/** The current block of the response that is being transferred. */
	private Response currentResponse; // Matching needs to know when receiving duplicate
	
	/** The status of the blockwise transfer. null in case of a normal transfer */
	private BlockwiseStatus responseBlockStatus;
	
	// indicates where the request of this exchange has been initiated.
	// (as suggested by effective Java, item 40.)
	private final Origin origin;
	
	// true if the exchange has failed due to a timeout
	private boolean timedOut;
	
	// the timeout of the current request or response set by reliability layer
	private int currentTimeout;
	
	// the amount of attempted transmissions that have not succeeded yet
	private int failedTransmissionCount = 0;

	// handle to cancel retransmission
	private ScheduledFuture<?> retransmissionHandle = null;

	// handle to extend blockwise status lifetime
	private ScheduledFuture<?> blockCleanupHandle = null;
	
	// If the request was sent with a block1 option the response has to send its
	// first block piggy-backed with the Block1 option of the last request block
	private BlockOption block1ToAck;
	
	// The relation that the target resource has established with the source
	private ObserveRelation relation;
	
	// When the request is handled by an executor different than the protocol stage set to true.
	// The endpoint will hand sending responses over to the protocol stage executor
	private boolean customExecutor = false;

	/**
	 * Constructs a new exchange with the specified request and origin. 
	 * @param request the request that starts the exchange
	 * @param origin the origin of the request (LOCAL or REMOTE)
	 */
	public Exchange(Request request, Origin origin) {
		INSTANCE_COUNTER.incrementAndGet();
		this.currentRequest = request; // might only be the first block of the whole request
		this.origin = origin;
		this.timestamp = System.currentTimeMillis();
	}
	
	/**
	 * Accept this exchange and therefore the request. Only if the request's
	 * type was a <code>CON</code> and the request has not been acknowledged
	 * yet, it sends an ACK to the client.
	 */
	public void sendAccept() {
		assert(origin == Origin.REMOTE);
		if (request.getType() == Type.CON && !request.isAcknowledged()) {
			request.setAcknowledged(true);
			EmptyMessage ack = EmptyMessage.newACK(request);
			endpoint.sendEmptyMessage(this, ack);
		}
	}
	
	/**
	 * Reject this exchange and therefore the request. Sends an RST back to the
	 * client.
	 */
	public void sendReject() {
		assert(origin == Origin.REMOTE);
		request.setRejected(true);
		EmptyMessage rst = EmptyMessage.newRST(request);
		endpoint.sendEmptyMessage(this, rst);
	}
	
	/**
	 * Sends the specified response over the same endpoint as the request has
	 * arrived.
	 * 
	 * @param response the response
	 */
	public void sendResponse(Response response) {
		response.setDestination(request.getSource());
		response.setDestinationPort(request.getSourcePort());
		setResponse(response);
		endpoint.sendResponse(this, response);
	}
	
	public Origin getOrigin() {
		return origin;
	}
	
	/**
	 * Returns the request that this exchange is associated with. If the request
	 * is sent blockwise, it might not have been assembled yet and this method
	 * returns null.
	 * 
	 * @return the complete request
	 * @see #getCurrentRequest()
	 */
	public Request getRequest() {
		return request;
	}
	
	/**
	 * Sets the request that this exchange is associated with.
	 * 
	 * @param request the request
	 * @see #setCurrentRequest(Request)
	 */
	public void setRequest(Request request) {
		this.request = request; // by blockwise layer
	}

	/**
	 * Returns the current request block. If a request is not being sent
	 * blockwise, the whole request counts as a single block and this method
	 * returns the same request as {@link #getRequest()}. Call getRequest() to
	 * access the assembled request.
	 * 
	 * @return the current request block
	 */
	public Request getCurrentRequest() {
		return currentRequest;
	}

	/**
	 * Sets the current request block. If a request is not being sent
	 * blockwise, the origin request (equal to getRequest()) should be set.
	 * 
	 * @param currentRequest the current request block
	 */
	public void setCurrentRequest(Request currentRequest) {
		this.currentRequest = currentRequest;
	}

	/**
	 * Returns the blockwise transfer status of the request or null if no one is
	 * set.
	 * 
	 * @return the status of the blockwise transfer of the request
	 */
	public BlockwiseStatus getRequestBlockStatus() {
		return requestBlockStatus;
	}

	/**
	 * Sets the blockwise transfer status of the request.
	 * 
	 * @param requestBlockStatus the blockwise transfer status
	 */
	public void setRequestBlockStatus(BlockwiseStatus requestBlockStatus) {
		this.requestBlockStatus = requestBlockStatus;
	}

	/**
	 * Returns the response to the request or null if no response has arrived
	 * yet. If there is an observe relation, the last received notification is
	 * the response.
	 * 
	 * @return the response
	 */
	public Response getResponse() {
		return response;
	}
	
	/**
	 * Sets the response.
	 * 
	 * @param response the response
	 */
	public void setResponse(Response response) {
		this.response = response;
	}

	/**
	 * Returns the current response block. If a response is not being sent
	 * blockwise, the whole response counts as a single block and this method
	 * returns the same request as {@link #getResponse()}. Call getResponse() to
	 * access the assembled response.
	 * 
	 * @return the current response block
	 */
	public Response getCurrentResponse() {
		return currentResponse;
	}

	/**
	 * Sets the current response block. If a response is not being sent
	 * blockwise, the origin request (equal to getResponse()) should be set.
	 * 
	 * @param currentResponse the current response block
	 */
	public void setCurrentResponse(Response currentResponse) {
		this.currentResponse = currentResponse;
	}

	/**
	 * Returns the blockwise transfer status of the response or null if no one 
	 * is set.
	 * 
	 * @return the status of the blockwise transfer of the response
	 */
	public BlockwiseStatus getResponseBlockStatus() {
		return responseBlockStatus;
	}

	/**
	 * Sets the blockwise transfer status of the response.
	 * 
	 * @param responseBlockStatus the blockwise transfer status
	 */
	public void setResponseBlockStatus(BlockwiseStatus responseBlockStatus) {
		this.responseBlockStatus = responseBlockStatus;
	}

	/**
	 * Returns the block option of the last block of a blockwise sent request.
	 * When the server sends the response, this block option has to be
	 * acknowledged.
	 * 
	 * @return the block option of the last request block or null
	 */
	public BlockOption getBlock1ToAck() {
		return block1ToAck;
	}

	/**
	 * Sets the block option of the last block of a blockwise sent request.
	 * When the server sends the response, this block option has to be
	 * acknowledged.
	 * 
	 * @param block1ToAck the block option of the last request block
	 */
	public void setBlock1ToAck(BlockOption block1ToAck) {
		this.block1ToAck = block1ToAck;
	}
	
	/**
	 * Returns the endpoint which has created and processed this exchange.
	 * 
	 * @return the endpoint
	 */
	public Endpoint getEndpoint() {
		return endpoint;
	}

	public void setEndpoint(Endpoint endpoint) {
		this.endpoint = endpoint;
	}

	public boolean isTimedOut() {
		return timedOut;
	}

	/**
	 * This method also cleans up the Matcher state by eventually calling the
	 * exchange observer.
	 */
	public void setTimedOut() {
		this.timedOut = true;
		// clean up
		this.setComplete();
	}

	public int getFailedTransmissionCount() {
		return failedTransmissionCount;
	}

	public void setFailedTransmissionCount(int failedTransmissionCount) {
		this.failedTransmissionCount = failedTransmissionCount;
	}

	public int getCurrentTimeout() {
		return currentTimeout;
	}

	public void setCurrentTimeout(int currentTimeout) {
		this.currentTimeout = currentTimeout;
	}

	public ScheduledFuture<?> getRetransmissionHandle() {
		return retransmissionHandle;
	}

	public void setRetransmissionHandle(ScheduledFuture<?> retransmissionHandle) {
		if (this.retransmissionHandle!=null) {
			// avoid race condition of multiple responses (e.g., notifications)
			synchronized (this) {
				if (this.retransmissionHandle!=null) {
					this.retransmissionHandle.cancel(false);
				}
			}
		}
		this.retransmissionHandle = retransmissionHandle;
	}

	public ScheduledFuture<?> getBlockCleanupHandle() {
		return blockCleanupHandle;
	}

	public void setBlockCleanupHandle(ScheduledFuture<?> blockCleanupHandle) {
		if (this.blockCleanupHandle!=null) {
			// avoid race condition of multiple block requests
			synchronized (this) {
				if (this.blockCleanupHandle!=null) {
					this.blockCleanupHandle.cancel(false);
				}
			}
		}
		this.blockCleanupHandle = blockCleanupHandle;
	}

	public void setObserver(ExchangeObserver observer) {
		this.observer = observer;
	}

	public boolean isComplete() {
		return complete;
	}

	/**
	 * Call this method to trigger a clean-up in the Matcher through its
	 * ExchangeObserverImpl. Usually, it is called automatically when reaching
	 * the StackTopAdapter in the {@link CoapStack}, when timing out, when
	 * rejecting a response, or when sending the (last) response.
	 */
	public void setComplete() {
		this.complete = true;
		ExchangeObserver obs = this.observer;
		if (obs != null)
			obs.completed(this);
	}
	
	/**
	 * This method is only needed when the same {@link Exchange} instance uses
	 * different tokens during its lifetime, e.g., when using a different token
	 * for retrieving the rest of a blockwise notification (when not altered,
	 * Californium reuses the same token for this).
	 * See {@link BlockwiseLayer} for an example use case.
	 */
	public void completeCurrentRequest() {
		ExchangeObserver obs = this.observer;
		if (obs != null)
			obs.completed(this);
	}

	public long getTimestamp() {
		return timestamp;
	}

	/**
	 * Returns the CoAP observe relation that this exchange has established.
	 * 
	 * @return the observe relation or null
	 */
	public ObserveRelation getRelation() {
		return relation;
	}

	/**
	 * Sets the observe relation this exchange has established.
	 * 
	 * @param relation the CoAP observe relation
	 */
	public void setRelation(ObserveRelation relation) {
		this.relation = relation;
	}

	/**
	 * Checks if this exchange was delivered to a handler with custom Executor.
	 * If so, the protocol stage must hand the processing over to its own Executor.
	 * Otherwise the exchange was handled directly by a protocol stage thread.
	 * 
	 * @return true if for handler with custom executor
	 */
	public boolean hasCustomExecutor() {
		return customExecutor;
	}

	/**
	 * Marks that this exchange was delivered to a handler with custom Executor.
	 * If so, the protocol stage must hand the processing over to its own Executor.
	 * Otherwise the exchange was handled directly by a protocol stage thread.
	 */
	public void setCustomExecutor() {
		this.customExecutor = true;
	}

	/**
	 * This class is used by the matcher to remember a message by its MID and
	 * source/destination.
	 */
	public static final class KeyMID {
		
		protected final int MID;
		protected final byte[] address;
		protected final int port;
		private final int hash;
		
		public KeyMID(int mid, byte[] address, int port) {
			this.MID = mid;
			this.address = address;
			this.port = port;
			this.hash = (port*31 + mid) * 31 + Arrays.hashCode(address);
		}
		
		@Override
		public int hashCode() {
			return hash;
		}
		
		@Override
		public boolean equals(Object o) {
			if (! (o instanceof KeyMID))
				return false;
			KeyMID key = (KeyMID) o;
			return MID == key.MID && port == key.port && Arrays.equals(address, key.address);
		}
		
		@Override
		public String toString() {
			return "KeyMID["+MID+" for "+Utils.toHexString(address)+":"+port+"]";
		}
	}
	
	/**
	 * This class is used by the matcher to remember a request by its token and
	 * destination.
	 */
	public static final class KeyToken {

		protected final byte[] token;
		private final int hash;

		public KeyToken(byte[] token) {
			if (token == null)
				throw new NullPointerException();
			this.token = token;
			this.hash = Arrays.hashCode(token);
		}
		
		@Override
		public int hashCode() {
			return hash;
		}
		
		@Override
		public boolean equals(Object o) {
			if (! (o instanceof KeyToken))
				return false;
			KeyToken key = (KeyToken) o;
			return Arrays.equals(token, key.token);
		}
		
		@Override
		public String toString() {
			return "KeyToken["+Utils.toHexString(token)+"]";
		}
	}
	
	/**
	 * This class is used by the matcher to remember a request by its 
	 * destination URI (for observe relations).
	 */
	public static class KeyUri {

		protected final String uri;
		protected final byte[] address;
		protected final int port;
		private final int hash;
		
		public KeyUri(String uri, byte[] address, int port) {
			if (uri == null) throw new NullPointerException();
			if (address == null) throw new NullPointerException();
			this.uri = uri;
			this.address = address;
			this.port = port;
			this.hash = (port*31 + uri.hashCode()) * 31 + Arrays.hashCode(address);
		}
		
		@Override
		public int hashCode() {
			return hash;
		}
		
		@Override
		public boolean equals(Object o) {
			if (! (o instanceof KeyUri))
				return false;
			KeyUri key = (KeyUri) o;
			return uri.equals(key.uri) && port == key.port && Arrays.equals(address, key.address);
		}
		
		@Override
		public String toString() {
			return "KeyUri["+uri+" for "+Utils.toHexString(address)+":"+port+"]";
		}
	}
}
