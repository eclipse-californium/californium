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
 *    Stefan Jucker - DTLS implementation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add convenience constructor for
 *                                                    setting the DTLS session
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 464383
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.TimerTask;

/**
 * A container for a set of DTLS records that are to be (re-)transmitted
 * as a whole on a DTLS connection.
 * 
 * DTLS messages are grouped into a series of message flights. One flight
 * consists of at least one message and needs to be re-transmitted until the
 * peer's next flight has arrived in its total. A flight needs not only consist of
 * {@link HandshakeMessage}s but may also contain {@link AlertMessage}s
 * and {@link ChangeCipherSpecMessage}s. See <a
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
	private int timeout = 0;

	/**
	 * Indicates, whether this flight needs retransmission (not every flight
	 * needs retransmission, e.g. Alert).
	 */
	private boolean retransmissionNeeded = false;

	/** The retransmission task. Needed when to cancel the retransmission. */
	private TimerTask retransmitTask;

	/**
	 * Initializes an empty, fresh flight. The timeout is set to 0, it will be
	 * set later by the standard duration.
	 * 
	 * @deprecated use other constructor
	 */
	@Deprecated
	public DTLSFlight() {
		this.messages = new ArrayList<Record>();
		this.tries = 0;
		this.timeout = 0;
	}
	
	/**
	 * Creates an empty flight to be sent to a given peer.
	 * 
	 * Flights created using this constructor are <em>not</em>
	 * eligible for re-transmission because there is no
	 * <code>DTLSSession</code> available to obtain record sequence
	 * numbers from.
	 * 
	 * @param peerAddress the IP address and port to send the records to
	 * @throws NullPointerException if peerAddress is <code>null</code>
	 */
	public DTLSFlight(InetSocketAddress peerAddress) {
		if (peerAddress == null) {
			throw new NullPointerException("Peer address must not be null");
		}
		this.peerAddress = peerAddress;
		this.messages = new ArrayList<Record>();
	}
	
	/**
	 * Creates an empty flight to be sent within a session with a peer.
	 * 
	 * Flights created using this constructor are by default eligible for
	 * re-transmission.
	 * 
	 * @param session the session to get record sequence numbers from
	 *                 when sending out the flight
	 * @throws NullPointerException if session is <code>null</code>
	 */
	public DTLSFlight(DTLSSession session) {
		this(session.getPeer());
		this.session = session;
		retransmissionNeeded = true;
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

	/**
	 * Sets the IP address and port to send the flight's messages to.
	 * 
	 * @param peerAddress the peer address
	 * @deprecated use the constructor to implicitly set the peer address
	 *                   as part of the provided session 
	 */
	@Deprecated
	public void setPeerAddress(InetSocketAddress peerAddress) {
		this.peerAddress = peerAddress;
	}

	public DTLSSession getSession() {
		return session;
	}

	/**
	 * Sets the session to get sequence numbers from when sending the
	 * flight's messages.
	 * 
	 * @param session the session
	 * @deprecated use the constructor to set the session
	 */
	@Deprecated
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
