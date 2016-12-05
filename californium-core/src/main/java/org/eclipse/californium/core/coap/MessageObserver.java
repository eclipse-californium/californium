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
package org.eclipse.californium.core.coap;


/**
 * A callback that gets invoked on a message's lifecycle events.
 * <p>
 * The following methods are called
 * <ul>
 * <li> {@link #onResponse(Response)} when a response arrives</li>
 * <li> {@link #onAcknowledgement()} when the message has been acknowledged</li>
 * <li> {@link #onReject()} when the message has been rejected</li>
 * <li> {@link #onTimeout()} when the client stops retransmitting the message and
 * still has not received anything from the remote endpoint</li>
 * <li> {@link #onCancel()} when the message has been canceled</li>
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
 */
public interface MessageObserver {

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
	 * For instance, a user might cancel a request or a CoAP resource that is being
	 * observed might cancel a response to send another one instead.
	 */
	void onCancel();
}
