/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Bosch Software Innovations GmbH - use correlation context to improve matching
 *                                      of Response(s) to Request (fix GitHub issue #1)
 *    Achim Kraus (Bosch Software Innovations GmbH) - add calculateRTT
 *                                                    use nanoTime instead of 
 *                                                    currentTimeMillis
 *    Achim Kraus (Bosch Software Innovations GmbH) - ensure states visibility for
 *                                                    different threads
 *    Achim Kraus (Bosch Software Innovations GmbH) - forward CorrelationContext only
 *                                                    for the first time set.
 *                                                    issue #311
 *    Achim Kraus (Bosch Software Innovations GmbH) - forward setTimedOut to messages.
 *    Achim Kraus (Bosch Software Innovations GmbH) - stop retransmission on complete.
 *    Achim Kraus (Bosch Software Innovations GmbH) - adjust javadoc for 
 *                                                    completeCurrentRequest.
 *    Achim Kraus (Bosch Software Innovations GmbH) - rename CorrelationContext to
 *                                                    EndpointContext.
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.stack.BlockwiseLayer;
import org.eclipse.californium.core.network.stack.CoapStack;
import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.EndpointContext;

/**
 * An exchange represents the complete state of an exchange of one request and
 * one or more responses. The lifecycle of an exchange ends when either the last
 * response has arrived and is acknowledged, when a request or response has been
 * rejected from the remote endpoint, when the request has been canceled, or
 * when a request or response timed out, i.e., has reached the retransmission
 * limit without being acknowledged.
 * <p>
 * The framework internally uses the class Exchange to manage an exchange of
 * {@link Request}s and {@link Response}s. The Exchange only contains state, no
 * functionality. The CoAP Stack contains the functionality of the CoAP protocol
 * and modifies the exchange appropriately. The class Exchange and its fields
 * are <em>NOT</em> thread-safe.
 * <p>
 * The class {@link CoapExchange} provides the corresponding API for developers.
 * Proceed with caution when using this class directly, e.g., through
 * {@link CoapExchange#advanced()}.
 * <p>
 * This class might change with the implementation of CoAP extensions.
 * <p>
 * Even if above mentions, that this class is not thread safe, its used from
 * several different threads! Generally the Exchanges are hand over via a
 * concurrent collections in the matcher and therefore establish a "happens
 * before" order (as long as threads accessing the exchange via the matcher).
 * But some methods are out of scope of that and use Exchange directly (e.g.
 * {@link #setEndpointContext(EndpointContext) the "sender thread" or
 * {@link #setFailedTransmissionCount(int)} the "retransmission thread
 * (executor)"). Therefore use at least volatile for the fields. This doesn't
 * ensure, that Exchange is thread safe, it only ensures the visibility of the
 * states.
 */
public class Exchange {

	private static final int MAX_OBSERVE_NO = (1 << 24) - 1;

	/**
	 * The origin of an exchange.
	 * <p>
	 * If Cf receives a new request and creates a new exchange the origin is
	 * REMOTE since the request has been initiated from a remote endpoint. If Cf
	 * creates a new request and sends it, the origin is LOCAL.
	 */
	public enum Origin {

		/**
		 * Indicates that a message exchange has been initiated locally.
		 */
		LOCAL,

		/**
		 * Indicates that a message exchange has been initiated remotely.
		 */
		REMOTE;
	}

	/**
	 * The endpoint that processes this exchange.
	 * 
	 * Set on receiving a message.
	 */
	private volatile Endpoint endpoint;

	/** An observer to be called when a request is complete */
	private volatile ExchangeObserver observer;

	/** Indicates if the exchange is complete */
	private volatile boolean complete = false;

	/** The nano timestamp when this exchange has been created */
	private final long nanoTimestamp;

	/**
	 * The actual request that caused this exchange. Layers below the
	 * {@link BlockwiseLayer} should only work with the {@link #currentRequest}
	 * while layers above should work with the {@link #request}.
	 */
	private volatile Request request; // the initial request we have to exchange

	/**
	 * The current block of the request that is being processed. This is a
	 * single block in case of a blockwise transfer or the same as
	 * {@link #request} in case of a normal transfer.
	 */
	// Matching needs to know for what we expect a response
	private volatile Request currentRequest;

	/**
	 * The actual response that is supposed to be sent to the client. Layers
	 * below the {@link BlockwiseLayer} should only work with the
	 * {@link #currentResponse} while layers above should work with the
	 * {@link #response}.
	 */
	private volatile Response response;

	/** The current block of the response that is being transferred. */
	// Matching needs to know when receiving duplicate
	private volatile Response currentResponse;

	// indicates where the request of this exchange has been initiated.
	// (as suggested by effective Java, item 40.)
	private final Origin origin;

	// true if the exchange has failed due to a timeout
	private volatile boolean timedOut;

	// the timeout of the current request or response set by reliability layer
	private volatile int currentTimeout;

	// the amount of attempted transmissions that have not succeeded yet
	private volatile int failedTransmissionCount = 0;

	// handle to cancel retransmission
	private final AtomicReference<ScheduledFuture<?>> retransmissionHandle = new AtomicReference<ScheduledFuture<?>>();

	// If the request was sent with a block1 option the response has to send its
	// first block piggy-backed with the Block1 option of the last request block
	private volatile BlockOption block1ToAck;

	private volatile Integer notificationNumber;

	// The relation that the target resource has established with the source
	private volatile ObserveRelation relation;

	// When the request is handled by an executor different than the protocol
	// stage set to true. The endpoint will hand sending responses over to the
	// protocol stage executor
	private volatile boolean customExecutor = false;

	private final AtomicReference<EndpointContext> endpointContext = new AtomicReference<EndpointContext>();

	/**
	 * Creates a new exchange with the specified request and origin.
	 * 
	 * @param request the request that starts the exchange
	 * @param origin the origin of the request (LOCAL or REMOTE)
	 */
	public Exchange(final Request request, final Origin origin) {
		// might only be the first block of the whole request
		this(request, origin, null);
	}

	/**
	 * Creates a new exchange with the specified request, origin and context.
	 * 
	 * @param request the request that starts the exchange
	 * @param origin the origin of the request (LOCAL or REMOTE)
	 * @param ctx the endpoint context of this exchange
	 */
	public Exchange(Request request, Origin origin, EndpointContext ctx) {
		// might only be the first block of the whole request
		this.currentRequest = request;
		this.origin = origin;
		this.endpointContext.set(ctx);
		this.nanoTimestamp = System.nanoTime();
	}

	/**
	 * Accept this exchange and therefore the request. Only if the request's
	 * type was a <code>CON</code> and the request has not been acknowledged
	 * yet, it sends an ACK to the client.
	 */
	public void sendAccept() {
		assert (origin == Origin.REMOTE);
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
		assert (origin == Origin.REMOTE);
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
		response.setDestinationContext(request.getSourceContext());
		setResponse(response);
		endpoint.sendResponse(this, response);
	}

	public Origin getOrigin() {
		return origin;
	}

	public boolean isOfLocalOrigin() {
		return origin == Origin.LOCAL;
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
	 * Sets the current request block. If a request is not being sent blockwise,
	 * the origin request (equal to getRequest()) should be set.
	 * 
	 * @param currentRequest the current request block
	 */
	public void setCurrentRequest(Request currentRequest) {
		this.currentRequest = currentRequest;
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
	 * Sets the block option of the last block of a blockwise sent request. When
	 * the server sends the response, this block option has to be acknowledged.
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

	/**
	 * Set endpoint of received message.
	 * 
	 * @param endpoint endpoint, which received the message.
	 */
	public void setEndpoint(Endpoint endpoint) {
		this.endpoint = endpoint;
	}

	/**
	 * Indicated, that this exchange retransmission reached the timeout.
	 * 
	 * @return {@code true}, transmission reached timeout, {@code false},
	 *         otherwise
	 */
	public boolean isTimedOut() {
		return timedOut;
	}

	/**
	 * Report transmission timeout for provided message to exchange.
	 * <p>
	 * This method also cleans up the Matcher state by calling the
	 * exchange observer {@link #setComplete()}. The timeout is forward to the
	 * provided message, and, for the {@link #currentRequest}, it is also
	 * forwarded to the {@link #request} to timeout the blockwise transfer
	 * itself.
	 * 
	 * @param message message, which transmission has reached the timeout.
	 */
	public void setTimedOut(Message message) {
		this.timedOut = true;
		// clean up
		this.setComplete();
		// forward timeout to message
		message.setTimedOut(true);
		Request request = this.request;
		if (request != null && currentRequest == message && request != message  ) {
			// forward timeout to request
			request.setTimedOut(true);
		}
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
		return retransmissionHandle.get();
	}

	public void setRetransmissionHandle(ScheduledFuture<?> retransmissionHandle) {
		// avoid race condition of multiple responses (e.g., notifications)
		ScheduledFuture<?> previous = this.retransmissionHandle.getAndSet(retransmissionHandle);
		if (previous != null) {
			previous.cancel(false);
		}
	}

	/**
	 * Sets the number of the notification this exchange is associated with.
	 * <p>
	 * This number can be used to match responses of a blockwise transfer
	 * triggered by a notification.
	 * 
	 * @param notificationNo The observe number of the notification.
	 * @throws IllegalArgumentException if the given number is &lt; 0 or &gt;
	 *             2^24 - 1.
	 */
	public void setNotificationNumber(final int notificationNo) {
		if (notificationNo < 0 || notificationNo > MAX_OBSERVE_NO) {
			throw new IllegalArgumentException("illegal observe number");
		}
		this.notificationNumber = notificationNo;
	}

	/**
	 * Gets the number of the notification this exchange is associated with.
	 * <p>
	 * This number can be used to match responses of a blockwise transfer
	 * triggered by a notification.
	 * 
	 * @return The observe number of the notification or {@code null} if this
	 *         exchange is not associated with a notification.
	 */
	public Integer getNotificationNumber() {
		return notificationNumber;
	}

	/**
	 * Sets an observer to be invoked when this exchange completes.
	 * 
	 * @param observer The observer.
	 */
	public void setObserver(ExchangeObserver observer) {
		this.observer = observer;
	}

	/**
	 * Checks whether this exchange has an observer registered.
	 * 
	 * @return {@code true} if an observer is registered.
	 * @see #setObserver(ExchangeObserver)
	 */
	public boolean hasObserver() {
		return observer != null;
	}

	/**
	 * Checks if this exchange has been marked as <em>completed</em>.
	 * 
	 * @return {@code true} if this exchange has been completed.
	 */
	public boolean isComplete() {
		return complete;
	}

	/**
	 * Marks this exchange as being <em>completed</em>.
	 * <p>
	 * This means that both request and response have been sent/received.
	 * <p>
	 * This method invokes the {@linkplain ExchangeObserver#completed(Exchange)
	 * completed} method on the observer registered on this exchange (if any).
	 * <p>
	 * Call this method to trigger a clean-up in the Matcher through its
	 * ExchangeObserverImpl. Usually, it is called automatically when reaching
	 * the StackTopAdapter in the {@link CoapStack}, when timing out, when
	 * rejecting a response, or when sending the (last) response.
	 */
	public void setComplete() {
		setRetransmissionHandle(null);
		this.complete = true;
		ExchangeObserver obs = this.observer;
		if (obs != null) {
			obs.completed(this);
		}
	}

	/**
	 * Complete exchange using the current request and response.
	 * 
	 * This method is only needed when the same {@link Exchange} instance uses
	 * different tokens or MIDs during its lifetime, e.g., when using a different
	 * token for retrieving the rest of a blockwise notification (when not altered,
	 * Californium reuses the same token for this). Or when different CON notifies
	 * are sent with different MIDs. 
	 * <p>
	 * See {@link BlockwiseLayer} or {@link ObserveLayer} for an example use case.
	 */
	public void completeCurrentRequest() {
		setRetransmissionHandle(null);
		ExchangeObserver obs = this.observer;
		if (obs != null) {
			obs.completed(this);
		}
	}

	/**
	 * Get the nano-timestamp of the creation of this exchange.
	 * 
	 * @return nano-timestamp
	 * @see System#nanoTime()
	 */
	public long getNanoTimestamp() {
		return nanoTimestamp;
	}

	/**
	 * Calculates the RTT (round trip time) of this exchange.
	 * 
	 * MUST be called on receiving the response.
	 * 
	 * @return RTT in milliseconds
	 */
	public long calculateRTT() {
		return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - nanoTimestamp);
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
	 * If so, the protocol stage must hand the processing over to its own
	 * Executor. Otherwise the exchange was handled directly by a protocol stage
	 * thread.
	 * 
	 * @return true if for handler with custom executor
	 */
	public boolean hasCustomExecutor() {
		return customExecutor;
	}

	/**
	 * Marks that this exchange was delivered to a handler with custom Executor.
	 * If so, the protocol stage must hand the processing over to its own
	 * Executor. Otherwise the exchange was handled directly by a protocol stage
	 * thread.
	 */
	public void setCustomExecutor() {
		this.customExecutor = true;
	}

	/**
	 * Sets additional information about the context this exchange's request has
	 * been sent in.
	 * <p>
	 * The information is usually obtained from the <code>Connector</code> this
	 * exchange is using to send and receive data. The information contained in
	 * the context can be used in addition to the message ID and token of this
	 * exchange to increase security when matching an incoming response to this
	 * exchange's request.
	 * </p>
	 * 
	 * @param ctx the endpoint context information
	 */
	public void setEndpointContext(final EndpointContext ctx) {
		if (endpointContext.compareAndSet(null, ctx)) {
			ExchangeObserver obs = this.observer;
			if (obs != null) {
				obs.contextEstablished(this);
			}
		} else {
			endpointContext.set(ctx);
		}
	}

	/**
	 * Gets transport layer specific information that can be used to correlate a
	 * response with this exchange's original request.
	 * 
	 * @return the endpoint context information or <code>null</code> if no
	 *         information is available.
	 */
	public EndpointContext getEndpointContext() {
		return endpointContext.get();
	}

	/**
	 * A CoAP message ID scoped to a remote endpoint.
	 * <p>
	 * This class is used by the matcher to correlate messages by MID and
	 * endpoint address.
	 */
	public static final class KeyMID {

		private static final int MAX_PORT_NO = (1 << 16) - 1;
		private final int MID;
		private final byte[] address;
		private final int port;
		private final int hash;

		/**
		 * Creates a key based on a message ID and a remote endpoint address.
		 * 
		 * @param mid the message ID.
		 * @param address the IP address of the remote endpoint.
		 * @param port the port of the remote endpoint.
		 * @throws NullPointerException if address or origin is {@code null}
		 * @throws IllegalArgumentException if mid or port &lt; 0 or &gt; 65535.
		 * 
		 */
		private KeyMID(final int mid, final byte[] address, final int port) {
			if (mid < 0 || mid > Message.MAX_MID) {
				throw new IllegalArgumentException("MID must be a 16 bit unsigned int: " + mid);
			} else if (address == null) {
				throw new NullPointerException("address must not be null");
			} else if (port < 0 || port > MAX_PORT_NO) {
				throw new IllegalArgumentException("Port must be a 16 bit unsigned int");
			} else {
				this.MID = mid;
				this.address = address;
				this.port = port;
				this.hash = createHashCode();
			}
		}

		@Override
		public int hashCode() {
			return hash;
		}

		private int createHashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + MID;
			result = prime * result + Arrays.hashCode(address);
			result = prime * result + port;
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			KeyMID other = (KeyMID) obj;
			if (MID != other.MID)
				return false;
			if (!Arrays.equals(address, other.address))
				return false;
			if (port != other.port)
				return false;
			return true;
		}

		@Override
		public String toString() {
			return new StringBuilder("KeyMID[").append(MID).append(", ").append(Utils.toHexString(address)).append(":")
					.append(port).append("]").toString();
		}

		/**
		 * Creates a key from an inbound CoAP message.
		 * 
		 * @param message the message.
		 * @return the key derived from the message. The key's <em>mid</em> is
		 *         scoped to the message's source address and port.
		 */
		public static KeyMID fromInboundMessage(Message message) {
			InetSocketAddress address = message.getSourceContext().getPeerAddress();
			return new KeyMID(message.getMID(), address.getAddress().getAddress(), address.getPort());
		}

		/**
		 * Creates a key from an outbound CoAP message.
		 * 
		 * @param message the message.
		 * @return the key derived from the message. The key's <em>mid</em> is
		 *         scoped to the message's destination address and port.
		 */
		public static KeyMID fromOutboundMessage(Message message) {
			InetSocketAddress address = message.getDestinationContext().getPeerAddress();
			return new KeyMID(message.getMID(), address.getAddress().getAddress(), address.getPort());
		}
	}

	/**
	 * A CoAP message token scoped to a remote endpoint.
	 * <p>
	 * This class is used by the matcher to correlate messages by their token
	 * and endpoint address.
	 */
	public static final class KeyToken {

		private static final int MAX_PORT_NO = (1 << 16) - 1;
		private final byte[] token;
		private final byte[] address;
		private final int port;
		private final int hash;

		private KeyToken(byte[] token, byte[] address, int port) {
			if (token == null) {
				throw new NullPointerException("token bytes must not be null");
			} else if (address == null) {
				throw new NullPointerException("address must not be null");
			} else if (port < 0 || port > MAX_PORT_NO) {
				throw new IllegalArgumentException("port must be a 16 bit unsigned int");
			}
			this.token = Arrays.copyOf(token, token.length);
			this.address = address;
			this.port = port;
			this.hash = createHash();
		}

		/**
		 * Creates a new key for an inbound CoAP message.
		 * <p>
		 * The key will be scoped to the message's source endpoint.
		 * 
		 * @param message the message.
		 * @return the key.
		 */
		public static KeyToken fromInboundMessage(final Message message) {
			InetSocketAddress address = message.getSourceContext().getPeerAddress();
			return new KeyToken(message.getToken(), address.getAddress().getAddress(), address.getPort());
		}

		/**
		 * Creates a new key for an outbound CoAP message.
		 * <p>
		 * The key will be scoped to the message's destination endpoint.
		 * 
		 * @param message the message.
		 * @return the key.
		 */
		public static KeyToken fromOutboundMessage(final Message message) {
			InetSocketAddress address = message.getDestinationContext().getPeerAddress();
			return new KeyToken(message.getToken(), address.getAddress().getAddress(), address.getPort());
		}

		/**
		 * Creates a new key for a token and an endpoint address.
		 * 
		 * @param token the token.
		 * @param address the endpoint's address.
		 * @param port the endpoint's port.
		 * @return the key.
		 * @throws NullPointerException if token or address is {@code null}
		 * @throws IllegalArgumentException if port &lt; 0 or port &gt; 65535.
		 */
		public static KeyToken fromValues(byte[] token, byte[] address, int port) {
			return new KeyToken(token, address, port);
		}

		private int createHash() {
			final int prime = 31;
			int result = 1;
			result = prime * result + port;
			result = prime * result + Arrays.hashCode(address);
			result = prime * result + Arrays.hashCode(token);
			return result;
		}

		@Override
		public String toString() {
			return new StringBuilder("KeyToken[").append(Utils.toHexString(token)).append(", ")
					.append(Utils.toHexString(address)).append(":").append(port).append("]").toString();
		}

		@Override
		public int hashCode() {
			return hash;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			KeyToken other = (KeyToken) obj;
			if (!Arrays.equals(address, other.address))
				return false;
			if (port != other.port)
				return false;
			if (!Arrays.equals(token, other.token))
				return false;
			return true;
		}

		public byte[] getToken() {
			return Arrays.copyOf(token, token.length);
		}
	}
}
