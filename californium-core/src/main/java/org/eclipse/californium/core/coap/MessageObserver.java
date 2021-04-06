/*******************************************************************************
 * Copyright (c) 2018 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add onSent() and onSendError()
 *                                                    issue #305
 *    Achim Kraus (Bosch Software Innovations GmbH) - add onReadyToSend() to fix rare
 *                                                    race condition in block1wise
 *                                                    when the generated token was 
 *                                                    copied too late (after sending). 
 *    Achim Kraus (Bosch Software Innovations GmbH) - move onContextEstablished
 *                                                    to MessageObserver.
 *                                                    Issue #487
 *    Achim Kraus (Bosch Software Innovations GmbH) - add onConnect
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import org.eclipse.californium.elements.EndpointContext;

/**
 * A callback that gets invoked on a message's life cycle events.
 * <p>
 * The following methods are called
 * <ul>
 * <li>{@link #onResponse(Response)} when a response arrives</li>
 * <li>{@link #onAcknowledgement()} when the message has been acknowledged</li>
 * <li>{@link #onReject()} when the message has been rejected</li>
 * <li>{@link #onTimeout()} when the client stops retransmitting the message and
 * still has not received anything from the remote endpoint</li>
 * <li>{@link #onCancel()} when the message has been canceled</li>
 * <li>{@link #onReadyToSend()} right before the message is being sent</li>
 * <li>{@link #onConnecting()} right before a connector establish a connection.
 * Not called, if the connection is already established or the connector doesn't
 * require to establish a connection.</li>
 * <li>{@link #onDtlsRetransmission(int)} when a dtls handshake flight is
 * retransmitted.</li>
 * <li>{@link #onSent(boolean)} right after the message has been sent
 * (successfully). The order of this callback related to
 * {@link #onAcknowledgement()} or {@link #onResponse(Response)} is undefined.
 * For some cases {@link #onContextEstablished(EndpointContext)} may be the
 * better choice.</li>
 * <li>{@link #onSendError(Throwable)} if the message cannot be sent</li>
 * <li>{@link #onResponseHandlingError(Throwable)} if an error happens during
 * response handling</li>
 * <li>{@link #onContextEstablished(EndpointContext)} when the resulting
 * endpoint context is reported by the connector, short before actually send the
 * message</li>
 * <li>{@link #onTransferComplete()} if transfer is successfully complete</li>
 * </ul>
 * <p>
 * The class that is interested in processing a message event either implements
 * this interface (and all the methods it contains) or extends the abstract
 * {@link MessageObserverAdapter} class (overriding only the methods of
 * interest).
 * <p>
 * The observer object created from that class is then registered with a message
 * using the message's {@link Message#addMessageObserver(MessageObserver)}
 * method.
 * <p>
 * Note: This class is unrelated to CoAP's observe relationship between an
 * endpoint and a resource. However, when a request establishes a CoAP observe
 * relationship to a resource which sends notifications, the method
 * {@link #onResponse(Response)} can be used to react to each such notification.
 * <p>
 * Note: Due to the execution model of Californium, all callbacks must be
 * processed in a none-blocking manner. Otherwise the performance will get
 * downgraded and deadlocks are risked. The order of the callbacks is also not
 * strictly defined. Especially {@link #onSent(boolean)} may be called after
 * {@link #onAcknowledgement()} or {@link #onResponse(Response)}.
 */
public interface MessageObserver {

	/**
	 * Check, if observer is internal and is not intended to be cloned.
	 * 
	 * @return {@code true}, internal, {@code false}, maybe cloned.
	 */
	boolean isInternal();

	/**
	 * Invoked when a message is about to be re-transmitted.
	 */
	void onRetransmission();

	/**
	 * Invoked when a response arrives.
	 * 
	 * @param response the response that arrives
	 */
	void onResponse(Response response);

	/**
	 * Invoked when the message has been acknowledged by the remote endpoint.
	 * 
	 * Note: since 3.0 this is only called for separate ACKs, not longer for
	 * piggy-backed responses.
	 */
	void onAcknowledgement();

	/**
	 * Invoked when the message has been rejected by the remote endpoint.
	 */
	void onReject();

	/**
	 * Invoked when the client stops retransmitting the message and still has
	 * not received anything from the remote endpoint.
	 * <p>
	 * By default this is the case after 5 unsuccessful transmission attempts.
	 */
	void onTimeout();

	/**
	 * Invoked when the message has been canceled.
	 * <p>
	 * For instance, a user might cancel a request or a CoAP resource that is
	 * being observed might cancel a response to send another one instead.
	 */
	void onCancel();

	/**
	 * Invoked when the message was built and is ready to be sent.
	 * <p>
	 * Triggered, before the message was sent by a connector. MID and token is
	 * prepared.
	 */
	void onReadyToSend();

	/**
	 * Invoked, when connector requires to establish a connection before sending
	 * the message.
	 */
	void onConnecting();

	/**
	 * Indicate, that this message triggered the connector to establish a
	 * connection and a dtls handshake flight was retransmitted.
	 * 
	 * @param flight {@code 1 ... 6}, number of retransmitted flight.
	 */
	void onDtlsRetransmission(int flight);

	/**
	 * Invoked right after the message has been sent.
	 * <p>
	 * Triggered, when the message was sent by a connector.
	 * 
	 * Note: the callback may occur "out of order" due the used threading!
	 * 
	 * @param retransmission {@code true}, if the message is sent by
	 *            retransmission, {@code false}, if the message is sent the
	 *            first time.
	 */
	void onSent(boolean retransmission);

	/**
	 * Invoked when sending the message caused an error.
	 * <p>
	 * For instance, if the message is not sent, because the endpoint context
	 * has changed.
	 * 
	 * @param error The cause of the failure to send the message.
	 */
	void onSendError(Throwable error);

	/**
	 * Invoked when an error happens during response handling.
	 * 
	 * @param cause The cause of the failure.
	 */
	void onResponseHandlingError(Throwable cause);

	/**
	 * Invoked when the resulting endpoint context is reported by the connector.
	 * 
	 * Note: usually this callback must be processed in a synchronous manner,
	 * because on returning, the message is sent. Therefore take special care in
	 * methods called on this callback.
	 * 
	 * @param endpointContext resulting endpoint context
	 */
	void onContextEstablished(EndpointContext endpointContext);

	/**
	 * Invoked, when transfer is successfully complete.
	 * 
	 * @since 3.0 (was onComplete())
	 */
	void onTransferComplete();
}
