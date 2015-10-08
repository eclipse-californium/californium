/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
 * An abstract adapter class for reacting to message events. The methods in this
 * class are empty. This class exists as convenience for creating message
 * observer objects.
 * <p>
 * The following methods are called
 * <ul>
 * <li> {@link #onResponse(Response)} when a response arrives</li>
 * <li> {@link #onAcknowledgement()} when the message has been acknowledged</li>
 * <li> {@link #onReject()} when the message has been rejected</li>
 * <li> {@link #onCancel()} when the message has been canceled</li>
 * <li> {@link #onTimeout()} when the client stops retransmitting the message and
 * still has not received anything from the remote endpoint</li>
 * </ul>
 * <p>
 * Extend this class to create a message observer and override the methods for
 * the events of interest. (If you implement the <code>MessageObserver</code>
 * interface, you have to define all of the methods in it. This abstract class
 * defines empty methods for them all, so you only have to define methods for
 * events you care about.)
 * <p>
 * Create a message observer using the extended class and then register it with
 * a message using the message's
 * <code>addMessageObserver(MessageObserver observer)</code> method.
 */
public abstract class MessageObserverAdapter implements MessageObserver {

	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.coap.MessageObserver#retransmitting()
	 */
	@Override
	public void onRetransmission() {
		// empty default implementation
	}
	
	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.coap.MessageObserver#responded(ch.inf.vs.californium.coap.Response)
	 */
	@Override
	public void onResponse(Response response) {
		// empty default implementation
	}

	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.coap.MessageObserver#acknowledged()
	 */
	@Override
	public void onAcknowledgement() {
		// empty default implementation
	}

	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.coap.MessageObserver#rejected()
	 */
	@Override
	public void onReject() {
		// empty default implementation
	}

	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.coap.MessageObserver#canceled()
	 */
	@Override
	public void onCancel() {
		// empty default implementation
	}

	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.coap.MessageObserver#timedOut()
	 */
	@Override
	public void onTimeout() {
		// empty default implementation
	}
}
