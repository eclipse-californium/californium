/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
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

import java.util.ArrayList;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

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

	private static final Logger LOGGER = LoggerFactory.getLogger(Exchange.class);
	
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
	 * The key mid for the current request.
	 */
	private KeyMID currentKeyMID;
	/**
	 * The key token for the original request, if {@link #keepRequestInStore} is
	 * {@code true}. {@code null} otherwise.
	 */
	private KeyToken originalKeyToken;
	/**
	 * The key token for the current request.
	 */
	private KeyToken currentKeyToken;

	/**
	 * The realtime in nanoseconds, just before the last message of this
	 * exchange was sent. {@code 0}, if no message was sent until now. In the
	 * extremely rare cases, that the realtime in nanosecond is actually
	 * {@code 0}, the value is adapted to {@code -1}.
	 */
	private final AtomicLong sendNanoTimestamp = new AtomicLong();

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

	/** The notifications that have been sent, so they can be removed from the Matcher */
	private volatile List<KeyMID> notifications;

	private final AtomicReference<EndpointContext> endpointContext = new AtomicReference<EndpointContext>();

	private volatile EndpointContextOperator endpointContextPreOperator;

	//If object security option is used, the Cryptographic context identifier is stored here
	// for request/response mapping of contexts
	private byte[] cryptoContextId;

	/**
	 * Creates a new exchange with the specified request and origin.
	 * 
	 * @param request the request that starts the exchange
	 * @param origin the origin of the request (LOCAL or REMOTE)
	 * @param executor executor to be used for exchanges. Maybe {@code null} for unit tests.
	 * @throws NullPointerException if request is {@code null}
	 */
	public Exchange(Request request, Origin origin, Executor executor) {
		this(request, origin, executor, null, false);
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
	 * @throws NullPointerException if request is {@code null}
	 */
	public Exchange(Request request, Origin origin, Executor executor, EndpointContext ctx, boolean notification) {
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
		this.keepRequestInStore = !notification && request.isObserve() && origin == Origin.LOCAL;
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
	 * yet, it sends an ACK to the client. Use the source endpoint context of
	 * the current request to send the ACK.
	 * 
	 * @see #sendAccept(EndpointContext)
	 */
	public void sendAccept() {
		assert (origin == Origin.REMOTE);
		sendAccept(currentRequest.getSourceContext());
	}

	/**
	 * Accept this exchange and therefore the request. Only if the request's
	 * type was a <code>CON</code> and the request has not been acknowledged
	 * yet, it sends an ACK to the client and prepares to send the response as
	 * separate response.
	 * 
	 * @param context endpoint context to send ack
	 * 
	 * @see #sendAccept()
	 */
	public void sendAccept(EndpointContext context) {
		assert (origin == Origin.REMOTE);
		Request current = currentRequest;
		if (current.getType() == Type.CON && current.hasMID() && current.acknowledge()) {
			EmptyMessage ack = EmptyMessage.newACK(current, context);
			endpoint.sendEmptyMessage(this, ack);
		}
	}

	/**
	 * Reject this exchange and therefore the request. Sends an RST back to the
	 * client, if the request has not been already rejected. Use the source
	 * endpoint context of the current request to send the RST.
	 * 
	 * Note: since 2.3, rejects for multicast requests are not sent. (See
	 * {@link MulticastReceivers#addMulticastReceiver(org.eclipse.californium.elements.Connector)
	 * for receiving multicast requests}.
	 * 
	 * @see #sendReject(EndpointContext)
	 * @since 2.3 rejects for multicast requests are not sent
	 */
	public void sendReject() {
		assert (origin == Origin.REMOTE);
		sendReject(currentRequest.getSourceContext());
	}

	/**
	 * Reject this exchange and therefore the request. Sends an RST back to the
	 * client, if the request has not been already rejected.
	 * 
	 * Note: since 2.3, rejects for multicast requests are not sent. (See
	 * {@link MulticastReceivers#addMulticastReceiver(org.eclipse.californium.elements.Connector)
	 * for receiving multicast requests}.
	 * 
	 * @param context endpoint context to send RST
	 * 
	 * @see #sendReject()
	 * @since 2.3 rejects for multicast requests are not sent
	 */
	public void sendReject(EndpointContext context) {
		assert (origin == Origin.REMOTE);
		Request current = currentRequest;
		if (current.hasMID() && !current.isRejected()) {
			current.setRejected(true);
			if (!current.isMulticast()) {
				EmptyMessage rst = EmptyMessage.newRST(current, context);
				endpoint.sendEmptyMessage(this, rst);
			}
		}
	}

	/**
	 * Sends the specified response over the same endpoint as the request has
	 * arrived.
	 * 
	 * If no destination context is provided, use the source context of the
	 * request.
	 * 
	 * Note: since 2.3, error responses for multicast requests are not sent. (See
	 * {@link MulticastReceivers#addMulticastReceiver(org.eclipse.californium.elements.Connector)
	 * for receiving multicast requests}.
	 * 
	 * @param response the response
	 * @since 2.3 error responses for multicast requests are not sent
	 */
	public void sendResponse(Response response) {
		Request current = currentRequest;
		if (current.isMulticast() && response.isError()) {
			return;
		}
		if (response.getDestinationContext() == null) {
			response.setDestinationContext(currentRequest.getSourceContext());
		}
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
	 * @throws ConcurrentModificationException if not executed within
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
	 * @throws ConcurrentModificationException if not executed within
	 *             {@link #execute(Runnable)}.
	 */
	public void setCurrentRequest(Request newCurrentRequest) {
		assertOwner();
		if (currentRequest != newCurrentRequest) {
			setRetransmissionHandle(null);
			failedTransmissionCount = 0;
			LOGGER.debug("{} replace {} by {}", this, currentRequest, newCurrentRequest);
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
	 * @throws ConcurrentModificationException if not executed within
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
	 * @throws ConcurrentModificationException if not executed within
	 *             {@link #execute(Runnable)}.
	 */
	public void setCurrentResponse(Response newCurrentResponse) {
		assertOwner();
		if (currentResponse != newCurrentResponse) {
			if (!isOfLocalOrigin() && currentKeyMID != null && currentResponse != null
					&& currentResponse.getType() == Type.NON && currentResponse.isNotification()) {
				// keep NON notifies in KeyMID store.
				LOGGER.info("{} store NON notification: {}", this, currentKeyMID);
				notifications.add(currentKeyMID);
				currentKeyMID = null;
			}
			currentResponse = newCurrentResponse;
		}
	}

	public KeyMID getKeyMID() {
		return currentKeyMID;
	}

	/**
	 * Set key mid used to register this exchange.
	 * 
	 * @param keyMID key mid.
	 * @throws ConcurrentModificationException if not executed within
	 *             {@link #execute(Runnable)}.
	 */
	public void setKeyMID(KeyMID keyMID) {
		assertOwner();
		if (!keyMID.equals(currentKeyMID)) {
			RemoveHandler handler = this.removeHandler;
			if (handler != null && currentKeyMID != null) {
				handler.remove(this, null, currentKeyMID);
			}
			currentKeyMID = keyMID;
		}
	}

	/**
	 * Set key token used to register this exchange.
	 * 
	 * @param keyToken key token
	 * @throws ConcurrentModificationException if not executed within
	 *             {@link #execute(Runnable)}.
	 */
	public void setKeyToken(KeyToken keyToken) {
		assertOwner();
		if (!isOfLocalOrigin()) {
			throw new IllegalStateException("Token is only supported for local exchanges!");
		}
		if (!keyToken.equals(currentKeyToken)) {
			RemoveHandler handler = this.removeHandler;
			if (handler != null && currentKeyToken != null && !currentKeyToken.equals(originalKeyToken)) {
				handler.remove(this, currentKeyToken, null);
			}
			currentKeyToken = keyToken;
			if (keepRequestInStore && originalKeyToken == null) {
				// keep the original key token
				originalKeyToken = keyToken;
			}
		}
	}

	public KeyToken getKeyToken() {
		return currentKeyToken;
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
	 * @throws ConcurrentModificationException if not executed within
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
	 * @throws ConcurrentModificationException if not executed within
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
	 * @throws ConcurrentModificationException if not executed within
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
	 * @return {@code true}, if this exchange has been completed.
	 */
	public boolean isComplete() {
		return complete.get();
	}

	/**
	 * Get caller.
	 * 
	 * @return the caller's stacktrace.
	 */
	public Throwable getCaller() {
		return caller;
	}

	/**
	 * Marks this exchange as being <em>completed</em>.
	 * <p>
	 * This means that both request and response have been sent/received.
	 * <p>
	 * This method invokes the {@linkplain RemoveHandler#remove(Exchange, KeyToken, KeyMID)
	 * remove} method on the observer registered on this exchange (if any).
	 * <p>
	 * Call this method to trigger a clean-up in the Matcher through its
	 * ExchangeObserverImpl. Usually, it is called automatically when reaching
	 * the StackTopAdapter in the {@link CoapStack}, when timing out, when
	 * rejecting a response, or when sending the (last) response.
	 * 
	 * @return {@code true}, if complete is set the first time, {@code false},
	 *         if it is repeated.
	 * @throws ExchangeCompleteException if exchange was already completed.
	 * @throws ConcurrentModificationException if not executed within
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
					if (currentKeyToken != null || currentKeyMID != null) {
						handler.remove(this, currentKeyToken, currentKeyMID);
					}
					if (currentKeyToken != originalKeyToken) {
						handler.remove(this, originalKeyToken, null);
					}
					if (LOGGER.isDebugEnabled()) {
						Request currrentRequest = getCurrentRequest();
						Request request = getRequest();
						if (request == currrentRequest) {
							LOGGER.debug("local {} completed {}!", this, request);
						} else {
							LOGGER.debug("local {} completed {} -/- {}!", this, request, currrentRequest);
						}
					}
				} else {
					Response currentResponse = getCurrentResponse();
					if (currentResponse == null) {
						LOGGER.debug("remote {} rejected (without response)!", this);
					} else {
						if (currentKeyMID != null) {
							handler.remove(this, null, currentKeyMID);
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
	 * Get the realtime of the last sending of a message in nanoseconds.
	 * 
	 * The realtime is just before sending this message to ensure, that the
	 * message wasn't sent up to this time. This will alos contain the realtime
	 * for ACK or RST messages.
	 * 
	 * @return nano-time of last message sending. {@code 0}, if no message was
	 *         sent until now. In the extremely rare cases, that the realtime in
	 *         nanosecond is actually {@code 0}, the value is adapted to
	 *         {@code -1}.
	 * @see ClockUtil#nanoRealtime()
	 */
	public long getSendNanoTimestamp() {
		return sendNanoTimestamp.get();
	}

	/**
	 * Set the realtime of the last sending of a message in nanoseconds.
	 * 
	 * @param nanoTimestamp realtime in nanoseconds.{@code 0}, if no message was
	 *            sent until now. In the extremely rare cases, that the realtime
	 *            in nanosecond is actually {@code 0}, the value must be adapted
	 *            to {@code -1}.
	 */
	public void setSendNanoTimestamp(long nanoTimestamp) {
		sendNanoTimestamp.set(nanoTimestamp);
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
	 * @throws ConcurrentModificationException if not executed within
	 *             {@link #execute(Runnable)}.
	 * @throws NullPointerException if provided relation is {@code null}
	 * @throws IllegalStateException if relation was already set before
	 */
	public void setRelation(ObserveRelation relation) {
		assertOwner();
		if (relation == null) {
			throw new NullPointerException("Observer relation must not be null!");
		}
		if (this.relation != null || notifications != null) {
			throw new IllegalStateException("Observer relation already set!");
		}
		this.relation = relation;
		notifications = new ArrayList<KeyMID>();
	}

	/**
	 * Remove past notifications from message exchange store.
	 * 
	 * To be able to react on RST for notifications, the NON notifications are
	 * also kept in the message exchange store. This method removes the
	 * notification message from the store.
	 * 
	 * @throws ConcurrentModificationException if not executed within
	 *             {@link #execute(Runnable)}.
	 */
	public void removeNotifications() {
		assertOwner();
		RemoveHandler handler = this.removeHandler;
		if (notifications != null && !notifications.isEmpty()) {
			for (KeyMID keyMid : notifications) {
				LOGGER.info("{} removing NON notification: {}", this, keyMid);
				// notifications are local MID namespace
				if (handler != null) {
					handler.remove(this, null, keyMid);
				}
			}
			notifications.clear();
			LOGGER.debug("{} removing all remaining NON-notifications of observe relation with {}", this,
					relation.getSource());
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
	 * If a {@link #setEndpointContextPreOperator(EndpointContextOperator)} is used,
	 * this pre-operator is called before the endpoint context is set and forwarded.
	 * 
	 * @param ctx the endpoint context information
	 */
	public void setEndpointContext(EndpointContext ctx) {
		EndpointContextOperator operator = endpointContextPreOperator;
		if (operator != null) {
			ctx = operator.apply(ctx);
		}
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
	 * Set endpoint context pre-operator.
	 * 
	 * Applied on {@link #setEndpointContext(EndpointContext)} before the
	 * endpoint context is set and forwarded.
	 * 
	 * @param operator preprocessing operator for endoint context.
	 */
	public void setEndpointContextPreOperator(EndpointContextOperator operator) {
		endpointContextPreOperator = operator;
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
	 * @throws ConcurrentModificationException if not executed within
	 *             {@link #execute(Runnable)}.
	 * @throws ExchangeCompleteException if exchange is already completed
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
	 * @throws ConcurrentModificationException if not executed within
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
	 * Sets cryptoContextId
	 * 
	 * @param cryptoContextId a byte array used for mapping cryptographic
	 *            contexts
	 */
	public void setCryptographicContextID(byte[] cryptoContextId) {
		this.cryptoContextId = cryptoContextId;
	}

	/**
	 * Gets cryptoContextId.
	 * 
	 * Used by OSCORE.
	 * 
	 * @return byte array with crypto context id.
	 */
	public byte[] getCryptographicContextID() {
		return this.cryptoContextId;
	}

	/**
	 * Endpoint context operator. Use to pre-process a reported endpoint context
	 * before set and forwarding it.
	 */
	public interface EndpointContextOperator {

		/**
		 * Apply operation on endpoint context.
		 * 
		 * @param context endpoint context
		 * @return resulting endpoint context.
		 */
		EndpointContext apply(EndpointContext context);
	}
}
