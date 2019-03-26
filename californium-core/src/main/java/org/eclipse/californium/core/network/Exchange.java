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
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove KeyToken,
 *                                                    replaced by Token
 *    Achim Kraus (Bosch Software Innovations GmbH) - use new ExchangeObserver.remove
 *                                                    for house-keeping. Introduce
 *                                                    keepRequestInStore for flexible
 *                                                    blockwise observe support.
 *    Achim Kraus (Bosch Software Innovations GmbH) - move onContextEstablished
 *                                                    to MessageObserver.
 *                                                    Issue #487
 *    Achim Kraus (Bosch Software Innovations GmbH) - add checkMID to support
 *                                                    rejection of previous notifications
 *    Achim Kraus (Bosch Software Innovations GmbH) - add check for hasMID before
 *                                                    sending ACK or RST.
 *                                                    (therefore tcp messages are not
 *                                                    rejected nor acknowledged)
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace striped executor
 *                                                    with serial executor
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.stack.BlockwiseLayer;
import org.eclipse.californium.core.network.stack.CoapStack;
import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.SerialExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
 * are <em>NOT</em> thread-safe. The setter methods must be called within a
 * {@link Runnable}, which must be executed using {@link #execute(Runnable)}.
 * For convenience the {@link #executeComplete()} is provided to execute
 * {@link #setComplete()} accordingly. Methods, which are documented to throw a
 * {@link ConcurrentModificationException} MUST comply to this execution
 * pattern!
 * <p>
 * If the exchange represents a "blockwise" transfer and if the transparent mode
 * is used, the exchange keeps also the (original) request and use the current
 * request for transfer the blocks. A request not using observe use the same
 * token for easier tracking. A request using observe keeps the origin request
 * with the origin token in store, but use a different token for the transfer of
 * the left blocks. This enables to catch new notifies while a transfer is
 * ongoing.
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
 * {@link #setEndpointContext(EndpointContext)} the "sender thread" or
 * {@link #setFailedTransmissionCount(int)} the "retransmission thread
 * (executor)"). Therefore use at least volatile for the fields. This doesn't
 * ensure, that Exchange is thread safe, it only ensures the visibility of the
 * states.
 */
public class Exchange {

	private static final Logger LOGGER = LoggerFactory.getLogger(Exchange.class.getName());
	
	static final boolean DEBUG = LOGGER.isTraceEnabled();

	private static final int MAX_OBSERVE_NO = (1 << 24) - 1;
	/**
	 * ID generator for logging messages.
	 */
	private static final AtomicInteger INSTANCE_COUNTER = new AtomicInteger();

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
	 * ID for logging.
	 */
	private final int id;
	/**
	 * Executor for exchange jobs.
	 * 
	 * Note: for unit tests this may be {@code null} to escape the owner checking.
	 * Otherwise many change in the tests would be required.
	 */
	private final SerialExecutor executor;
	/**
	 * Caller of {@link #setComplete()}. Intended for debug logging.
	 */
	private Throwable caller;

	/**
	 * The endpoint that processes this exchange.
	 * 
	 * Set on receiving a message.
	 */
	private volatile Endpoint endpoint;

	/** An remove handler to be called when a exchange must be removed from the exchange store */
	private volatile RemoveHandler removeHandler;

	/** Indicates if the exchange is complete */
	private final AtomicBoolean complete = new AtomicBoolean();

	/** The nano timestamp when this exchange has been created */
	private final long nanoTimestamp;

	/**
	 * Enable to keep the original request in the exchange store. Intended to be
	 * used for observe request with blockwise response to be able to react on
	 * newer notifies during an ongoing transfer.
	 */
	private final boolean keepRequestInStore;

	/**
	 * Mark exchange as notification.
	 */
	private final boolean notification;

	/**
	 * The actual request that caused this exchange. Layers below the
	 * {@link BlockwiseLayer} should only work with the {@link #currentRequest}
	 * while layers above should work with the {@link #request}.
	 */
	// the initial request we have to exchange
	private volatile Request request;

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
	private ScheduledFuture<?> retransmissionHandle;

	// If the request was sent with a block1 option the response has to send its
	// first block piggy-backed with the Block1 option of the last request block
	private volatile BlockOption block1ToAck;

	private volatile Integer notificationNumber;

	// The relation that the target resource has established with the source
	private volatile ObserveRelation relation;

	private final AtomicReference<EndpointContext> endpointContext = new AtomicReference<EndpointContext>();

	//If object security option is used, the Cryptographic context identifier is stored here
    // for request/response mapping of contexts
    private byte[] cryptoContextId;
	
	/**
	 * Creates a new exchange with the specified request and origin.
	 * 
	 * @param request the request that starts the exchange
	 * @param origin the origin of the request (LOCAL or REMOTE)
	 * @param executor executor to be used for exchanges. Maybe {@code null} for unit tests.
	 * @throws NullPointerException, if request is {@code null}
	 */
	public Exchange(Request request, Origin origin, Executor executor) {
		this(request, origin, executor, null, request != null && request.isObserve(), false);
	}

	/**
	 * Creates a new exchange with the specified request, origin, context, and
	 * notification marker.
	 * 
	 * @param request the request that starts the exchange
	 * @param origin the origin of the request (LOCAL or REMOTE)
	 * @param executor executor to be used for exchanges. Maybe {@code null} for unit tests.
	 * @param ctx the endpoint context of this exchange
	 * @param notification {@code true} for notification exchange, {@code false}
	 *            otherwise
	 * @throws NullPointerException, if request is {@code null}
	 */
	public Exchange(Request request, Origin origin, Executor executor, EndpointContext ctx, boolean notification) {
		this(request, origin, executor, ctx, request != null && request.isObserve() && !notification, notification);
	}

	/**
	 * Creates a new exchange with the specified request, origin and context.
	 * 
	 * @param request the request that starts the exchange
	 * @param origin the origin of the request (LOCAL or REMOTE)
	 * @param executor executor to be used for exchanges. Maybe {@code null} for unit tests.
	 * @param ctx the endpoint context of this exchange
	 * @param keepRequestInStore {@code true}, to keep the original request in
	 *            store until completed, {@code false} otherwise.
	 * @param notification {@code true} for notification exchange, {@code false}
	 *            otherwise
	 * @throws NullPointerException, if request is {@code null}
	 */
	private Exchange(Request request, Origin origin, Executor executor, EndpointContext ctx, boolean keepRequestInStore,
			boolean notification) {
		// might only be the first block of the whole request
		if (request == null) {
			throw new NullPointerException("request must not be null!");
		}
		this.id = INSTANCE_COUNTER.incrementAndGet();
		this.executor = SerialExecutor.create(executor);
		this.currentRequest = request;
		this.request = request;
		this.origin = origin;
		this.endpointContext.set(ctx);
		this.keepRequestInStore = keepRequestInStore;
		this.notification = notification;
		this.nanoTimestamp = ClockUtil.nanoRealtime();
	}

	@Override
	public String toString() {
		char originMarker = origin == Origin.LOCAL ? 'L' : 'R';
		if (complete.get()) {
			return "Exchange[" + originMarker + id + ", complete]";
		} else {
			return "Exchange[" + originMarker + id + "]";
		}
	}

	/**
	 * Accept this exchange and therefore the request. Only if the request's
	 * type was a <code>CON</code> and the request has not been acknowledged
	 * yet, it sends an ACK to the client.
	 */
	public void sendAccept() {
		assert (origin == Origin.REMOTE);
		Request current = currentRequest;
		if (current.getType() == Type.CON && current.hasMID() && !current.isAcknowledged()) {
			current.setAcknowledged(true);
			EmptyMessage ack = EmptyMessage.newACK(current);
			endpoint.sendEmptyMessage(this, ack);
		}
	}

	/**
	 * Reject this exchange and therefore the request. Sends an RST back to the
	 * client.
	 */
	public void sendReject() {
		assert (origin == Origin.REMOTE);
		Request current = currentRequest;
		if (current.hasMID() && !current.isRejected()) {
			current.setRejected(true);
			EmptyMessage rst = EmptyMessage.newRST(current);
			endpoint.sendEmptyMessage(this, rst);
		}
	}

	/**
	 * Sends the specified response over the same endpoint as the request has
	 * arrived.
	 * 
	 * @param response the response
	 */
	public void sendResponse(Response response) {
		Request current = currentRequest;
		response.setDestinationContext(current.getSourceContext());
		endpoint.sendResponse(this, response);
	}

	public Origin getOrigin() {
		return origin;
	}

	public boolean isOfLocalOrigin() {
		return origin == Origin.LOCAL;
	}

	/**
	 * Indicate to keep the original request in the exchange store. Intended to
	 * be used for observe request with blockwise response to be able to react
	 * on newer notifies during an ongoing transfer.
	 * 
	 * @return {@code true} to keep it, {@code false}, otherwise
	 */
	public boolean keepsRequestInStore() {
		return keepRequestInStore;
	}

	/**
	 * Indicate a notification exchange.
	 * 
	 * @return {@code true} if notification is exchanged, {@code false},
	 *         otherwise
	 */
	public boolean isNotification() {
		return notification;
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
	 * @param newRequest the request
	 * @throws ConcurrentModificationException, if not executed within
	 *             {@link #execute(Runnable)}.
	 * @see #setCurrentRequest(Request)
	 */
	public void setRequest(Request newRequest) {
		assertOwner();
		if (request != newRequest) {
			if (keepRequestInStore) {
				Token token = request.getToken();
				if (token != null && !token.equals(newRequest.getToken())) {
					throw new IllegalArgumentException(
							this + " token missmatch (" + token + "!=" + newRequest.getToken() + ")!");
				}
			}
			request = newRequest;
		}
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
	 * @param newCurrentRequest the current request block
	 * @throws ConcurrentModificationException, if not executed within
	 *             {@link #execute(Runnable)}.
	 */
	public void setCurrentRequest(Request newCurrentRequest) {
		assertOwner();
		if (currentRequest != newCurrentRequest) {
			setRetransmissionHandle(null);
			failedTransmissionCount = 0;
			Token token = currentRequest.getToken();
			if (token != null) {
				if (token.equals(newCurrentRequest.getToken())) {
					token = null;
				} else if (keepRequestInStore && token.equals(request.getToken())) {
					token = null;
				}
			}
			KeyMID key = null;
			if (currentRequest.hasMID() && currentRequest.getMID() != newCurrentRequest.getMID()) {
				key = KeyMID.fromOutboundMessage(currentRequest);
			}
			if (token != null || key != null) {
				LOGGER.debug("{} replace {} by {}", this, currentRequest, newCurrentRequest);
				RemoveHandler obs = this.removeHandler;
				if (obs != null) {
					obs.remove(this, token, key);
				}
			}
			currentRequest = newCurrentRequest;
		}
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
	 * @throws ConcurrentModificationException, if not executed within
	 *             {@link #execute(Runnable)}.
	 */
	public void setResponse(Response response) {
		assertOwner();
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
	 * @param newCurrentResponse the current response block
	 * @throws ConcurrentModificationException, if not executed within
	 *             {@link #execute(Runnable)}.
	 */
	public void setCurrentResponse(Response newCurrentResponse) {
		assertOwner();
		if (currentResponse != newCurrentResponse) {
			if (currentResponse != null && currentResponse.getType() == Type.CON && currentResponse.hasMID()) {
				RemoveHandler handler = this.removeHandler;
				if (handler != null) {
					KeyMID key = KeyMID.fromOutboundMessage(currentResponse);
					handler.remove(this, null, key);
				}
			}
			currentResponse = newCurrentResponse;
		}
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
	 * This method also cleans up the Matcher state by calling the exchange
	 * observer {@link #setComplete()}. The timeout is forward to the provided
	 * message, and, for the {@link #currentRequest}, it is also forwarded to
	 * the {@link #request} to timeout the blockwise transfer itself. If the
	 * exchange was already completed, this method doesn't forward the timeout
	 * calls to the requests.
	 * 
	 * @param message message, which transmission has reached the timeout.
	 * @throws ConcurrentModificationException, if not executed within
	 *             {@link #execute(Runnable)}.
	 */
	public void setTimedOut(Message message) {
		assertOwner();
		LOGGER.debug("{} timed out {}!", this, message);
		if (!isComplete()) {
			setComplete();
			this.timedOut = true;
			// forward timeout to message
			message.setTimedOut(true);
			if (request != null && request != message && currentRequest == message) {
				// forward timeout to request
				request.setTimedOut(true);
			}
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
		return retransmissionHandle;
	}

	/**
	 * Set retransmission handle.
	 * 
	 * @param newRetransmissionHandle
	 * @throws ConcurrentModificationException, if not executed within
	 *             {@link #execute(Runnable)}.
	 */
	public void setRetransmissionHandle(ScheduledFuture<?> newRetransmissionHandle) {
		assertOwner();
		if (!complete.get() || newRetransmissionHandle == null) {
			// avoid race condition of multiple responses (e.g., notifications)
			ScheduledFuture<?> previous = retransmissionHandle;
			retransmissionHandle = newRetransmissionHandle;
			if (previous != null) {
				previous.cancel(false);
			}
		}
	}

	/**
	 * Prepare exchange for retransmit a response.
	 * 
	 * @throws IllegalStateException if exchange is not a REMOTE exchange.
	 * @throws ConcurrentModificationException, if not executed within
	 *             {@link #execute(Runnable)}.
	 */
	public void retransmitResponse() {
		assertOwner();
		if (origin == Origin.REMOTE) {
			caller = null;
			complete.set(false);
		} else {
			throw new IllegalStateException(this + " retransmit on local exchange not allowed!");
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
			throw new IllegalArgumentException(this + " illegal observe number");
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
	 * Sets an remove handler to be invoked when this exchange completes.
	 * 
	 * @param removeHandler The remove handler.
	 */
	public void setRemoveHandler(RemoveHandler removeHandler) {
		this.removeHandler = removeHandler;
	}

	/**
	 * Checks whether this exchange has an remove handler set.
	 * 
	 * @return {@code true} if an remove handler is set.
	 * @see #setRemoveHandler(RemoveHandler)
	 */
	public boolean hasRemoveHandler() {
		return removeHandler != null;
	}

	/**
	 * Checks if this exchange has been marked as <em>completed</em>.
	 * 
	 * @return {@code true} if this exchange has been completed.
	 */
	public boolean isComplete() {
		return complete.get();
	}

	/**
	 * Get caller
	 */
	public Throwable getCaller() {
		return caller;
	}

	/**
	 * Marks this exchange as being <em>completed</em>.
	 * <p>
	 * This means that both request and response have been sent/received.
	 * <p>
	 * This method invokes the {@linkplain RemoveHandler#remove(Exchange, Token, KeyMID)
	 * remove} method on the observer registered on this exchange (if any).
	 * <p>
	 * Call this method to trigger a clean-up in the Matcher through its
	 * ExchangeObserverImpl. Usually, it is called automatically when reaching
	 * the StackTopAdapter in the {@link CoapStack}, when timing out, when
	 * rejecting a response, or when sending the (last) response.
	 * 
	 * @return {@code true}, if complete is set the first time, {@code false},
	 *         if it is repeated.
	 * @throws ExchangeCompleteException, if exchange was already completed.
	 * @throws ConcurrentModificationException, if not executed within
	 *             {@link #execute(Runnable)}.
	 */
	public boolean setComplete() {
		assertOwner();
		if (complete.compareAndSet(false, true)) {
			if (DEBUG) {
				caller = new Throwable(toString());
				if (LOGGER.isTraceEnabled()) {
					LOGGER.trace("{}!", this, caller);
				} else {
					LOGGER.debug("{}!", this);
				}
			} else {
				LOGGER.debug("{}!", this);
			}
			setRetransmissionHandle(null);
			RemoveHandler handler = this.removeHandler;
			if (handler != null) {
				if (origin == Origin.LOCAL) {
					Request currrentRequest = getCurrentRequest();
					Token token = currrentRequest.getToken();
					KeyMID key = currrentRequest.hasMID() ? KeyMID.fromOutboundMessage(currrentRequest) : null;
					if (token != null || key != null) {
						handler.remove(this, token, key);
					}
					Request request = getRequest();
					if (keepRequestInStore) {
						if (request != currrentRequest) {
							token = request.getToken();
							key = request.hasMID() ? KeyMID.fromOutboundMessage(request) : null;
							if (token != null || key != null) {
								handler.remove(this, token, key);
							}
						}
					}
					if (request == currrentRequest) {
						LOGGER.debug("local {} completed {}!", this, request);
					} else {
						LOGGER.debug("local {} completed {} -/- {}!", this, request, currrentRequest);
					}
				} else {
					Response currentResponse = getCurrentResponse();
					if (currentResponse == null) {
						LOGGER.debug("remote {} rejected (without response)!", this);
					} else {
						if (currentResponse.getType() == Type.CON && currentResponse.hasMID()) {
							KeyMID key = KeyMID.fromOutboundMessage(currentResponse);
							handler.remove(this, null, key);
						}
						removeNotifications();
						Response response = getResponse();
						if (response == currentResponse || response == null) {
							LOGGER.debug("Remote {} completed {}!", this, currentResponse);
						} else {
							LOGGER.debug("Remote {} completed {} -/- {}!", this, response, currentResponse);
						}
					}
				}
			}
			return true;
		} else {
			throw new ExchangeCompleteException(this + " already complete!", caller);
		}
	}

	/**
	 * Execute complete.
	 * 
	 * Schedules job for this exchange, if current thread is not already owner
	 * of it.
	 * 
	 * @return {@code true}, if exchange was not already completed,
	 *         {@code false}, if exchange is already completed.
	 */
	public boolean executeComplete() {
		if (complete.get()) {
			return false;
		}
		if (executor == null || checkOwner()) {
			setComplete();
		} else {
			execute(new Runnable() {

				@Override
				public void run() {
					if (!complete.get()) {
						setComplete();
					}
				}
			});
		}
		return true;
	}

	/**
	 * Get the nano-timestamp of the creation of this exchange.
	 * 
	 * @return nano-timestamp
	 * @see ClockUtil#nanoRealtime()
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
		return TimeUnit.NANOSECONDS.toMillis(ClockUtil.nanoRealtime() - nanoTimestamp);
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
	 * Remove past notifications from message exchange store.
	 * 
	 * To be able to react on RST for notifications, the NON notifications are
	 * also kept in the message exchange store. This method removes the
	 * notification message from the store.
	 * 
	 * @throws ConcurrentModificationException, if not executed within
	 *             {@link #execute(Runnable)}.
	 */
	public void removeNotifications() {
		assertOwner();
		ObserveRelation relation = this.relation;
		RemoveHandler handler = this.removeHandler;
		if (relation != null) {
			boolean removed = false;
			for (Iterator<Response> iterator = relation.getNotificationIterator(); iterator.hasNext();) {
				Response previous = iterator.next();
				LOGGER.debug("{} removing NON notification: {}", this, previous);
				// notifications are local MID namespace
				if (previous.hasMID()) {
					if (handler != null) {
						KeyMID key = KeyMID.fromOutboundMessage(previous);
						handler.remove(this, null, key);
					}
				} else {
					previous.cancel();
				}
				iterator.remove();
				removed = true;
			}
			if (removed) {
				LOGGER.debug("{} removing all remaining NON-notifications of observe relation with {}", this,
						relation.getSource());
			}
		}
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
			getCurrentRequest().onContextEstablished(ctx);
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
	 * Execute a job serialized related to this exchange.
	 * 
	 * If exchange is already owned by the current thread, execute it
	 * synchronous. Otherwise schedule the execution.
	 * 
	 * @param command job
	 */
	public void execute(final Runnable command) {
		try {
			if (executor == null || checkOwner()) {
				command.run();
			} else {
				executor.execute(command);
			}
		} catch (RejectedExecutionException e) {
			LOGGER.debug("{} execute:", this, e);
		} catch (Throwable t) {
			LOGGER.error("{} execute:", this, t);
		}
	}

	/**
	 * Assert, that the exchange is not complete and new messages could be send
	 * using this exchange.
	 * 
	 * @param message message to be send using this exchange.
	 * @throws ConcurrentModificationException, if not executed within
	 *             {@link #execute(Runnable)}.
	 * @throws ExchangeCompleteException, if exchange is already completed
	 */
	public void assertIncomplete(Object message) {
		assertOwner();
		if (complete.get()) {
			throw new ExchangeCompleteException(this + " is already complete! " + message, caller);
		}
	}

	/**
	 * Assert, that the current thread owns this exchange.
	 *
	 * @throws ConcurrentModificationException, if not executed within
	 *             {@link #execute(Runnable)}.
	 */
	private void assertOwner() {
		if (executor != null) {
			executor.assertOwner();
		}
	}

	/**
	 * Check, if current thread owns this exchange.
	 * 
	 * @return {@code true}, if current thread owns this exchange,
	 *         {@code false}, otherwise.
	 */
	public boolean checkOwner() {
		if (executor != null) {
			return executor.checkOwner();
		} else {
			return true;
		}
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
	 * Sets cryptoContextId
	 * 
	 * @param cryptoContextId a byte array used for mapping cryptographic
	 *            contexts
	 */
	public void setCryptographicContextID(byte[] cryptoContextId) {
		this.cryptoContextId = cryptoContextId;
	}

	/**
	 * Gets cryptoContextId
	 * 
	 * @return
	 */
	public byte[] getCryptographicContextID() {
		return this.cryptoContextId;
	}
}
