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
 *    Stefan Jucker - DTLS implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.TimerTask;

/**
 * DTLS messages are grouped into a series of message flights. One flight
 * contains of at least one message and needs to be retransmitted until the
 * peer's next flight has arrived in its total. A flight does not only exist of
 * {@link HandshakeMessage}, but also of {@link AlertMessage} and
 * {@link ChangeCipherSpecMessage}. See <a
 * href="http://tools.ietf.org/html/rfc6347#section-4.2.4">RFC 6347</a> for
 * details.
 */
public class DTLSFlight {

	/**
	 * The DTLS messages that belong to this flight and need to be sent, when
	 * the timeout expires.
	 */
	private List<Record> messages;

	/** The peer's address. */
	private InetSocketAddress peerAddress;

	/**
	 * The current DTLS session with the peer. Needed to set the record sequence
	 * number correctly when retransmitted.
	 */
	private DTLSSession session;

	/** The number of retransmissions. */
	private int tries;

	/** The current timeout (in milliseconds). */
	private int timeout;

	/**
	 * Indicates, whether this flight needs retransmission (not every flight
	 * needs retransmission, e.g. Alert).
	 */
	private boolean retransmissionNeeded = true;

	/** The retransmission task. Needed when to cancel the retransmission. */
	private TimerTask retransmitTask;

	/**
	 * Initializes an empty, fresh flight. The timeout is set to 0, it will be
	 * set later by the standard duration.
	 */
	public DTLSFlight() {
		this.messages = new ArrayList<Record>();
		this.tries = 0;
		this.timeout = 0;
	}
	
	public void addMessage(List<Record> message) {
		messages.addAll(message);
	}

	public void addMessage(Record message) {
		messages.add(message);
	}

	public List<Record> getMessages() {
		return messages;
	}

	public InetSocketAddress getPeerAddress() {
		return peerAddress;
	}

	public void setPeerAddress(InetSocketAddress peerAddress) {
		this.peerAddress = peerAddress;
	}

	public DTLSSession getSession() {
		return session;
	}

	public void setSession(DTLSSession session) {
		this.session = session;
	}

	public int getTries() {
		return tries;
	}

	public void incrementTries() {
		this.tries++;
	}

	public void setTries(int tries) {
		this.tries = tries;
	}

	public int getTimeout() {
		return timeout;
	}

	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}

	/**
	 * Called, when the flight needs to be retransmitted. Increment the timeout,
	 * here we double it.
	 */
	public void incrementTimeout() {
		this.timeout *= 2;
	}

	public boolean isRetransmissionNeeded() {
		return retransmissionNeeded;
	}

	public void setRetransmissionNeeded(boolean needsRetransmission) {
		this.retransmissionNeeded = needsRetransmission;
	}

	public TimerTask getRetransmitTask() {
		return retransmitTask;
	}

	public void setRetransmitTask(TimerTask retransmitTask) {
		this.retransmitTask = retransmitTask;
	}

}
