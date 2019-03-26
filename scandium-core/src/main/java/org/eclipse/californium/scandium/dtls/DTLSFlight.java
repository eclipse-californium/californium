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
 *    Stefan Jucker - DTLS implementation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add convenience constructor for
 *                                                    setting the DTLS session
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 464383
 *    Kai Hudalla (Bosch Software Innovations GmbH) - move code to set new sequence numbers
 *                                                    from DTLSConnector here
 *    Achim Kraus (Bosch Software Innovations GmbH) - make access to retransmission task
 *                                                    thread safe. Deprecate constructor
 *                                                    with InetSocketAddress
 *    Achim Kraus (Bosch Software Innovations GmbH) - add isRetransmissionCancelled
 *                                                    to stop retransmission when already
 *                                                    hand over to other executor
 *    Achim Kraus (Bosch Software Innovations GmbH) - add dtls flight number
 *    Achim Kraus (Bosch Software Innovations GmbH) - redesign using response started, 
 *                                                    response completed, and timeout
 *                                                    task
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ScheduledFuture;

import org.eclipse.californium.elements.MessageCallback;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;

/**
 * A container for a set of DTLS records that are to be (re-)transmitted as a
 * whole on a DTLS connection.
 * 
 * DTLS messages are grouped into a series of message flights. One flight
 * consists of at least one message and needs to be re-transmitted until the
 * peer's next flight has arrived in its total. A flight needs not only consist
 * of {@code HandshakeMessage}s but may also contain {@code AlertMessage}s and
 * {@code ChangeCipherSpecMessage}s. See
 * <a href="http://tools.ietf.org/html/rfc6347#section-4.2.4">RFC 6347</a> for
 * details.
 * 
 * Scandium offers also the possibility to stop the retransmission with
 * receiving the first response message instead of the complete fight. That is
 * currently configurable using
 * {@link DtlsConnectorConfig#isEarlyStopRetransmission()}. Only for the flight
 * before the very last flight of a handshake, it must be ensured, that the
 * retransmission is only stopped, after that very last flight is received
 * completely. Though the very last flight in DTLS 1.2 is always a flight with
 * CCS and FINISH, the implementation just use message of type handshake to stop
 * the retransmissions.
 * 
 * Even with stopped retransmission, a flight may timeout a handshake, if the
 * handshake response could not received completely. That timeout with stopped
 * retransmission is implemented using the timeout of the current try/retry and
 * the timeout used for the retry, when the maximum number of retries is
 * reached.
 * 
 * To support both variants, the flight provides the {@link #responseStarted}
 * and {@link #responseCompleted} flags and a general handle to a timeout task.
 * 
 * @see "e-mail discussion IETF TLS mailarchive, 
 *       2017, May 31. - June 1., Simone Bernard and Raja Ashok"
 */
public class DTLSFlight {

	/**
	 * The DTLS messages that belong to this flight and need to be sent, when
	 * the timeout expires.
	 */
	private final List<Record> messages;

	/** The peer's address. */
	private final InetSocketAddress peerAddress;

	/**
	 * The current DTLS session with the peer. Needed to set the record sequence
	 * number correctly when retransmitted.
	 */
	private final DTLSSession session;

	/**
	 * The number of the flight.
	 * 
	 * See RFC6347, page 21.
	 * 
	 * Note: californium sometimes also use a HelloVerifyRequest for resumption,
	 * therefore the numbers are incremented!
	 */
	private final int flightNumber;

	/** The number of retransmissions. */
	private int tries;

	/** The current timeout (in milliseconds). */
	private int timeout = 0;

	/**
	 * Indicates, whether this flight needs retransmission.
	 * The very last flight  (not every flight
	 * needs retransmission, e.g. Alert).
	 */
	private boolean retransmissionNeeded = false;

	/**
	 * Indicates, that the first handshake message of the response is received.
	 */
	private volatile boolean responseStarted;

	/**
	 * Indicates, that the response is received completely.
	 */
	private volatile boolean responseCompleted;

	/**
	 * The scheduled timeout task. Used to cancel the timeout task, if the
	 * response could be received completely within the timeout and retries.
	 */
	private ScheduledFuture<?> timeoutTask;

	/**
	 * Creates an empty flight to be sent within a session with a peer.
	 * 
	 * Flights created using this constructor are by default eligible for
	 * re-transmission.
	 * 
	 * @param session the session to get record sequence numbers from when
	 *            sending out the flight
	 * @param flightNumber number of the flight. Used for logging and
	 *            {@link MessageCallback#onDtlsRetransmission(int)}.
	 * @throws NullPointerException if session or peer address of session is
	 *             <code>null</code>
	 */
	public DTLSFlight(DTLSSession session, int flightNumber) {
		if (session == null) {
			throw new NullPointerException("Session must not be null");
		}
		if (session.getPeer() == null) {
			throw new NullPointerException("Peer address must not be null");
		}
		this.session = session;
		this.peerAddress = session.getPeer();
		this.messages = new ArrayList<Record>();
		this.retransmissionNeeded = true;
		this.flightNumber = flightNumber;
	}

	/**
	 * Adds a single message to this flight.
	 * 
	 * @param messageToAdd the message to add.
	 */
	public void addMessage(final Record messageToAdd) {
		this.messages.add(messageToAdd);
	}

	/**
	 * Gets the messages to be sent as part of this flight.
	 * 
	 * @return an unmodifiable list of the messages.
	 */
	public List<Record> getMessages() {
		return Collections.unmodifiableList(messages);
	}

	public InetSocketAddress getPeerAddress() {
		return peerAddress;
	}

	public DTLSSession getSession() {
		return session;
	}

	public int getFlightNumber() {
		return flightNumber;
	}

	public int getTries() {
		return tries;
	}

	public void incrementTries() {
		this.tries++;
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

	/**
	 * Indicates, that first handshake message of the response is received.
	 * 
	 * @return {@code true}, if the first handshake message of the response is
	 *         received, {@code false}, otherwise.
	 */
	public boolean isResponseStarted() {
		return responseStarted;
	}

	/**
	 * Signal, that the first handshake message of the response is received. If
	 * {@link DtlsConnectorConfig#isEarlyStopRetransmission()} is configured,
	 * this stops sending retransmissions but keep a scheduled timeout task.
	 */
	public void setResponseStarted() {
		responseStarted = true;
	}

	/**
	 * Cancel timeout task.
	 */
	private final void cancelTimeout() {
		if (timeoutTask != null) {
			if (!timeoutTask.isDone()) {
				timeoutTask.cancel(true);
			}
			timeoutTask = null;
		}
	}

	/**
	 * Cancels retransmission of this flight.
	 * 
	 * Response flight is received completely.
	 * 
	 * Note: a already cancelled flight could not be restarted using
	 * {@link #setTimeoutTask(ScheduledFuture)}.
	 */
	public void setResponseCompleted() {
		responseCompleted = true;
		cancelTimeout();
	}

	/**
	 * Check, if retransmission was cancelled.
	 * 
	 * @return {@code true}, if retransmission was cancelled, {@code false}, otherwise.
	 */
	public boolean isResponseCompleted() {
		return responseCompleted;
	}

	/**
	 * Set scheduled task.
	 * 
	 * Cancel a previous task, if not already done. If retransmission for this
	 * flight is already cancelled, the new scheduled task will also be
	 * cancelled. This prevents the flight from being retransmitted due to a
	 * race condition of receiving a message and executing the retransmission
	 * task in parallel.
	 * 
	 * @param timeoutTask new retransmit or timeout task.
	 */
	public void setTimeoutTask(final ScheduledFuture<?> timeoutTask) {
		if (responseCompleted) {
			timeoutTask.cancel(true);
		} else {
			cancelTimeout();
			this.timeoutTask = timeoutTask;
		}
	}

	/**
	 * Sets new sequence numbers on the records contained in this flight.
	 * 
	 * @throws GeneralSecurityException if setting a new sequence number on a record requires
	 *          recalculation of the MAC and the calculation fails.
	 * @throws IllegalStateException if this flight is not a retransmission (<code>tries == 0</code>)
	 *          or the DTLS session is <code>null</code>.
	 */
	public void setNewSequenceNumbers() throws GeneralSecurityException {
		if (getTries() > 0 && session != null) {
			for (Record record : messages) {
				// adjust the record sequence number
				int epoch = record.getEpoch();
				record.updateSequenceNumber(session.getSequenceNumber(epoch));
			}
		} else {
			throw new IllegalStateException("Can only set new sequence numbers for retransmitted flight with session");
		}
	}

}
