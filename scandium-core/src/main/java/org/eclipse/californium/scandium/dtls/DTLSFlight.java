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

import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.MessageCallback;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A container for a set of DTLS records that are to be (re-)transmitted as a
 * whole on a DTLS connection.
 * 
 * DTLS messages are grouped into a series of message flights. One flight
 * consists of at least one message and needs to be re-transmitted until the
 * peer's next flight has arrived in its total. A flight needs not only consist
 * of {@code HandshakeMessage}s but may also contain {@code AlertMessage}s and
 * {@code ChangeCipherSpecMessage}s. See
 * <a href="https://tools.ietf.org/html/rfc6347#section-4.2.4" target=
 * "_blank">RFC 6347</a> for details.
 * 
 * Scandium offers also the possibility to stop the retransmission with
 * receiving the first response message instead of the complete flight. That is
 * currently configurable using
 * {@link DtlsConnectorConfig#useEarlyStopRetransmission()}. Only for the flight
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
 * @see "e-mail discussion IETF TLS mailarchive, 2017, May 31. - June 1., Simone
 *      Bernard and Raja Ashok"
 */
@NoPublicAPI
public class DTLSFlight {

	private static final Logger LOGGER = LoggerFactory.getLogger(DTLSFlight.class);

	/**
	 * List of prepared records of flight.
	 */
	private final List<Record> records;

	/**
	 * The dtls messages together with their epoch that belong to this flight.
	 * 
	 * @since 2.4
	 */
	private final List<EpochMessage> dtlsMessages;

	/**
	 * The current DTLS context with the peer. Needed to set the record sequence
	 * number correctly when retransmitted.
	 */
	private final DTLSContext context;

	private final InetSocketAddress peer;

	private final Object peerToLog;

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
	private int timeoutMillis;

	/**
	 * Maximum datagram size.
	 * 
	 * @since 2.4
	 */
	private int maxDatagramSize;
	/**
	 * Maximum fragment size.
	 * 
	 * @since 2.4
	 */
	private int maxFragmentSize;
	/**
	 * Effective maximum datagram size.
	 * 
	 * The smaller resulting datagram size of {@link #maxDatagramSize} and
	 * {@link #maxFragmentSize}.
	 * 
	 * @since 3.0 (renamed, was effectiveDatagramSize9
	 */
	private int effectiveMaxDatagramSize;
	/**
	 * Effective maximum message size.
	 * 
	 * The resulting message size of {@link #maxDatagramSize} and
	 * {@link #maxFragmentSize} and cipher suite.
	 * 
	 * @since 3.0
	 */
	private int effectiveMaxMessageSize;

	/**
	 * Use dtls records with multiple handshake messages.
	 * 
	 * @since 2.4
	 */
	private boolean useMultiHandshakeMessageRecords;

	/**
	 * Epoch of current {@link MultiHandshakeMessage}.
	 * 
	 * @since 2.4
	 */
	private int multiEpoch;
	/**
	 * Use CID for the current {@link MultiHandshakeMessage}.
	 * 
	 * @since 2.4
	 */
	private boolean multiUseCid;
	/**
	 * Collect handshake messages for one dtls record.
	 * 
	 * @since 2.4
	 */
	private MultiHandshakeMessage multiHandshakeMessage;

	/**
	 * Indicates, whether this flight needs retransmission. The very last flight
	 * (not every flight needs retransmission, e.g. Alert).
	 */
	private boolean retransmissionNeeded;

	/**
	 * Indicates, whether this flight includes a {@link Finished} message, or
	 * not.
	 * 
	 * @see #addDtlsMessage(int, DTLSMessage)
	 * @since 3.9
	 */
	private boolean finishedIncluded;

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
	 * @param context the DTLS context to get record sequence numbers from when
	 *            sending out the flight
	 * @param flightNumber number of the flight. Used for logging and
	 *            {@link MessageCallback#onDtlsRetransmission(int)}.
	 * @param peer destination peer address
	 * @throws NullPointerException if context is {@code null}
	 */
	public DTLSFlight(DTLSContext context, int flightNumber, InetSocketAddress peer) {
		if (context == null) {
			throw new NullPointerException("Session must not be null");
		}
		this.context = context;
		this.peer = peer;
		this.peerToLog = StringUtil.toLog(peer);
		this.records = new ArrayList<Record>();
		this.dtlsMessages = new ArrayList<EpochMessage>();
		this.retransmissionNeeded = true;
		this.flightNumber = flightNumber;
	}

	/**
	 * Adds a dtls message to this flight.
	 * 
	 * Sets {@link #finishedIncluded} to {@code true}, if provided message is a
	 * {@link Finished} message.
	 * 
	 * @param epoch the epoch of the dtls message.
	 * @param messageToAdd the dtls message to add.
	 * @since 2.4
	 */
	public void addDtlsMessage(int epoch, DTLSMessage messageToAdd) {
		if (messageToAdd == null) {
			throw new NullPointerException("message must not be null!");
		}
		if (messageToAdd instanceof Finished) {
			finishedIncluded = true;
		}
		dtlsMessages.add(new EpochMessage(epoch, messageToAdd));
	}

	/**
	 * Get number of dtls messages of this flight.
	 * 
	 * @return number of dtls messages
	 * @since 2.4
	 */
	public int getNumberOfMessages() {
		return dtlsMessages.size();
	}

	/**
	 * Check, if the provided message is contained in this flight.
	 * 
	 * @param message message to check
	 * @return {@code true}, if message is contained, {@code false}, if not.
	 * @since 2.5
	 */
	public boolean contains(DTLSMessage message) {
		for (EpochMessage epochMessage : dtlsMessages) {
			if (Arrays.equals(message.toByteArray(), epochMessage.message.toByteArray())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Wraps a DTLS message into (potentially multiple) DTLS records and add
	 * them to the flight.
	 * 
	 * Sets the record's epoch, sequence number and handles fragmentation for
	 * handshake messages.
	 * 
	 * @param epochMessage dtls message and epoch
	 * @throws HandshakeException if the message could not be encrypted using
	 *             the session's current security parameters
	 * @since 2.4
	 */
	protected final void wrapMessage(EpochMessage epochMessage) throws HandshakeException {

		try {
			DTLSMessage message = epochMessage.message;
			switch (message.getContentType()) {
			case HANDSHAKE:
				wrapHandshakeMessage(epochMessage);
				break;
			case CHANGE_CIPHER_SPEC:
				flushMultiHandshakeMessages();
				// CCS has only 1 byte payload and doesn't require fragmentation
				records.add(new Record(message.getContentType(), epochMessage.epoch, message, context, false, 0));
				LOGGER.debug("Add CCS message of {} bytes for [{}]", message.size(), peerToLog);
				break;
			default:
				throw new HandshakeException("Cannot create " + message.getContentType() + " record for flight",
						new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR));
			}
		} catch (GeneralSecurityException e) {
			throw new HandshakeException("Cannot create record",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR), e);
		}
	}

	/**
	 * Wrap handshake messages into {@link MultiHandshakeMessage} or fragments,
	 * if handshake message is too large.
	 * 
	 * @param epochMessage handshake message and epoch
	 * @throws GeneralSecurityException if the message could not be encrypted
	 *             using the session's current security parameters
	 * @since 2.4
	 */
	private void wrapHandshakeMessage(EpochMessage epochMessage) throws GeneralSecurityException {
		HandshakeMessage handshakeMessage = (HandshakeMessage) epochMessage.message;
		int maxPayloadLength = maxDatagramSize - Record.RECORD_HEADER_BYTES;
		int effectiveMaxMessageSize;
		boolean useCid = false;

		if (epochMessage.epoch > 0) {
			ConnectionId connectionId = context.getWriteConnectionId();
			if (connectionId != null && !connectionId.isEmpty()) {
				useCid = true;
				// reduce fragment length by connection id
				maxPayloadLength -= connectionId.length();
			}
		}

		if (maxFragmentSize >= maxPayloadLength) {
			effectiveMaxMessageSize = maxPayloadLength;
			effectiveMaxDatagramSize = maxDatagramSize;
		} else {
			effectiveMaxMessageSize = maxFragmentSize;
			effectiveMaxDatagramSize = maxFragmentSize + (maxDatagramSize - maxPayloadLength);
		}

		if (epochMessage.epoch > 0) {
			effectiveMaxMessageSize -= context.getSession().getMaxCiphertextExpansion();
			if (useCid) {
				// reduce message length by  inner record type
				--effectiveMaxMessageSize;
			}
		}

		this.effectiveMaxMessageSize = effectiveMaxMessageSize;

		int messageSize = handshakeMessage.size();

		if (messageSize <= effectiveMaxMessageSize) {
			if (useMultiHandshakeMessageRecords) {
				if (multiHandshakeMessage != null) {
					if (multiEpoch == epochMessage.epoch && multiUseCid == useCid
							&& multiHandshakeMessage.size()
									+ messageSize < effectiveMaxMessageSize) {
						multiHandshakeMessage.add(handshakeMessage);
						LOGGER.debug("Add multi-handshake-message {} message of {} bytes, resulting in {} bytes for [{}]",
								handshakeMessage.getMessageType(), messageSize, multiHandshakeMessage.getMessageLength(), peerToLog);
						return;
					}
					flushMultiHandshakeMessages();
				}
				if (multiHandshakeMessage == null) {
					if (messageSize < effectiveMaxMessageSize) {
						multiHandshakeMessage = new MultiHandshakeMessage();
						multiHandshakeMessage.add(handshakeMessage);
						multiEpoch = epochMessage.epoch;
						multiUseCid = useCid;
						LOGGER.debug("Start multi-handshake-message with {} message of {} bytes for [{}]",
								handshakeMessage.getMessageType(), messageSize, peerToLog);
						return;
					}
				}
			}
			records.add(new Record(ContentType.HANDSHAKE, epochMessage.epoch, handshakeMessage, context, useCid, 0));
			LOGGER.debug("Add {} message of {} bytes for [{}]", handshakeMessage.getMessageType(), messageSize,
					peerToLog);
			return;
		}

		flushMultiHandshakeMessages();

		// message needs to be fragmented
		LOGGER.debug("Splitting up {} message of {} bytes for [{}] into multiple handshake fragments of max. {} bytes",
				handshakeMessage.getMessageType(), messageSize, peerToLog, effectiveMaxMessageSize);
		// create N handshake messages, all with the
		// same message_seq value as the original handshake message
		byte[] messageBytes = handshakeMessage.fragmentToByteArray();
		int handshakeMessageLength = handshakeMessage.getMessageLength();
		int maxHandshakeMessageLength = effectiveMaxMessageSize - HandshakeMessage.MESSAGE_HEADER_LENGTH_BYTES;
		if (messageBytes.length != handshakeMessageLength) {
			throw new IllegalStateException(
					"message length " + handshakeMessageLength + " differs from message " + messageBytes.length + "!");
		}
		int messageSeq = handshakeMessage.getMessageSeq();
		int offset = 0;
		while (offset < handshakeMessageLength) {
			int fragmentLength = maxHandshakeMessageLength;
			if (offset + fragmentLength > handshakeMessageLength) {
				// the last fragment is normally shorter than the maximal size
				fragmentLength = handshakeMessageLength - offset;
			}
			byte[] fragmentBytes = new byte[fragmentLength];
			System.arraycopy(messageBytes, offset, fragmentBytes, 0, fragmentLength);

			FragmentedHandshakeMessage fragmentedMessage = new FragmentedHandshakeMessage(
					handshakeMessage.getMessageType(), handshakeMessageLength, messageSeq, offset, fragmentBytes);

			LOGGER.debug("fragment for offset {}, {} bytes", offset, fragmentedMessage.size());

			offset += fragmentLength;

			records.add(new Record(ContentType.HANDSHAKE, epochMessage.epoch, fragmentedMessage, context, false, 0));
		}
	}

	/**
	 * Wrap pending handshake messages in a dtls record.
	 * 
	 * @throws GeneralSecurityException if the message could not be encrypted
	 *             using the session's current security parameters
	 */
	private void flushMultiHandshakeMessages() throws GeneralSecurityException {
		if (multiHandshakeMessage != null) {
			records.add(new Record(ContentType.HANDSHAKE, multiEpoch, multiHandshakeMessage, context, multiUseCid, 0));
			int count = multiHandshakeMessage.getNumberOfHandshakeMessages();
			LOGGER.debug("Add {} multi handshake message, epoch {} of {} bytes (max. {}) for [{}]", count, multiEpoch,
					multiHandshakeMessage.getMessageLength(), effectiveMaxMessageSize, peerToLog);
			multiHandshakeMessage = null;
			multiEpoch = 0;
			multiUseCid = false;
		}
	}

	/**
	 * Get wrapped records for flight.
	 * 
	 * @param maxDatagramSize maximum datagram size
	 * @param maxFragmentSize maximum fragment size
	 * @param useMultiHandshakeMessageRecords enable to use dtls records with
	 *            multiple handshake messages.
	 * @return list of records
	 * @throws HandshakeException if the message could not be encrypted using
	 *             the session's current security parameters
	 * @since 2.4
	 */
	public List<Record> getRecords(int maxDatagramSize, int maxFragmentSize, boolean useMultiHandshakeMessageRecords)
			throws HandshakeException {
		try {
			if (this.maxDatagramSize == maxDatagramSize && this.maxFragmentSize == maxFragmentSize
					&& this.useMultiHandshakeMessageRecords == useMultiHandshakeMessageRecords) {
				for (int index = 0; index < records.size(); ++index) {
					Record record = records.get(index);
					int epoch = record.getEpoch();
					DTLSMessage fragment = record.getFragment();
					boolean useCid = record.useConnectionId();
					records.set(index, new Record(record.getType(), epoch, fragment, context, useCid, 0));
				}
			} else {
				this.effectiveMaxDatagramSize = maxDatagramSize;
				this.maxDatagramSize = maxDatagramSize;
				this.maxFragmentSize = maxFragmentSize;
				this.useMultiHandshakeMessageRecords = useMultiHandshakeMessageRecords;
				records.clear();
				for (EpochMessage message : dtlsMessages) {
					wrapMessage(message);
				}
				flushMultiHandshakeMessages();
			}
		} catch (GeneralSecurityException e) {
			records.clear();
			throw new HandshakeException("Cannot create record",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR), e);
		}
		return records;
	}

	/**
	 * List of datagrams to be sent for this flight.
	 * 
	 * @param maxDatagramSize maximum datagram size
	 * @param maxFragmentSize maximum fragment size
	 * @param useMultiHandshakeMessageRecords enable to use dtls records with
	 *            multiple handshake messages.
	 * @param useMultiRecordMessages use datagrams with multiple dtls records
	 * @param backOff send flight in back off mode.
	 * @return list of datagrams
	 * @throws HandshakeException if the message could not be encrypted using
	 *             the session's current security parameters
	 * @since 2.4
	 */
	public List<DatagramPacket> getDatagrams(int maxDatagramSize, int maxFragmentSize,
			Boolean useMultiHandshakeMessageRecords, Boolean useMultiRecordMessages, boolean backOff)
			throws HandshakeException {

		DatagramWriter writer = new DatagramWriter(maxDatagramSize);
		List<DatagramPacket> datagrams = new ArrayList<DatagramPacket>();

		boolean multiHandshakeMessages = Boolean.TRUE.equals(useMultiHandshakeMessageRecords);
		boolean multiRecords = !Boolean.FALSE.equals(useMultiRecordMessages);

		if (backOff) {
			maxDatagramSize = Math.min(RecordLayer.DEFAULT_IPV4_MTU - RecordLayer.IPV4_HEADER_LENGTH, maxDatagramSize);
		}

		LOGGER.trace("Prepare flight {}, using max. datagram size {}, max. fragment size {} [mhm={}, mr={}]",
				flightNumber, maxDatagramSize, maxFragmentSize, multiHandshakeMessages, multiRecords);

		List<Record> records = getRecords(maxDatagramSize, maxFragmentSize, multiHandshakeMessages);

		LOGGER.trace("Effective max. datagram size {}, max. message size {}", effectiveMaxDatagramSize, effectiveMaxMessageSize);

		for (int index = 0; index < records.size(); ++index) {
			Record record = records.get(index);
			byte[] recordBytes = record.toByteArray();
			if (recordBytes.length > effectiveMaxDatagramSize) {
				LOGGER.error("{} record of {} bytes for peer [{}] exceeds max. datagram size [{}], discarding...",
						record.getType(), recordBytes.length, peerToLog, effectiveMaxDatagramSize);
				LOGGER.debug("{}", record);
				// TODO: inform application layer, e.g. using error handler
				continue;
			}
			LOGGER.trace("Sending record of {} bytes to peer [{}]:\n{}", recordBytes.length, peerToLog, record);
			if (multiRecords && record.getType() == ContentType.CHANGE_CIPHER_SPEC) {
				++index;
				if (index < records.size()) {
					Record finish = records.get(index);
					recordBytes = Bytes.concatenate(recordBytes, finish.toByteArray());
				}
			}
			int left = multiRecords && !(backOff && useMultiRecordMessages == null)
					? effectiveMaxDatagramSize - recordBytes.length
					: 0;
			if (writer.size() > left) {
				// current record does not fit into datagram anymore
				// thus, send out current datagram and put record into new one
				byte[] payload = writer.toByteArray();
				DatagramPacket datagram = new DatagramPacket(payload, payload.length, peer.getAddress(),
						peer.getPort());
				datagrams.add(datagram);
				LOGGER.debug("Sending datagram of {} bytes to peer [{}]", payload.length, peerToLog);
			}

			writer.writeBytes(recordBytes);
		}

		byte[] payload = writer.toByteArray();
		DatagramPacket datagram = new DatagramPacket(payload, payload.length, peer.getAddress(), peer.getPort());
		datagrams.add(datagram);
		LOGGER.debug("Sending datagram of {} bytes to peer [{}]", payload.length, peerToLog);
		writer = null;
		return datagrams;
	}

	/**
	 * Gets the effective maximum message size of the last
	 * {@link #getDatagrams(int, int, Boolean, Boolean, boolean)}.
	 * 
	 * @return the effective maximum message size
	 * @since 3.0
	 */
	public int getEffectiveMaxMessageSize() {
		return effectiveMaxMessageSize;
	}

	/**
	 * Get the flight number.
	 * 
	 * @return flight number
	 */
	public int getFlightNumber() {
		return flightNumber;
	}

	/**
	 * Get number of (re-)tries.
	 * 
	 * @return number of (re-)tries
	 */
	public int getTries() {
		return tries;
	}

	/**
	 * Increment number of (re-)tries.
	 */
	public void incrementTries() {
		this.tries++;
	}

	/**
	 * Get timeout.
	 * 
	 * @return timeout in milliseconds.
	 */
	public int getTimeout() {
		return timeoutMillis;
	}

	/**
	 * Set timeout.
	 * 
	 * @param timeoutMillis timeout in milliseconds.
	 */
	public void setTimeout(int timeoutMillis) {
		this.timeoutMillis = timeoutMillis;
	}

	/**
	 * Called, when the flight needs to be retransmitted.
	 * 
	 * Increment the timeout, scale it by the provided factor. Limit the timeout
	 * to the maximum timeout.
	 * 
	 * @param scale timeout scale
	 * @param maxTimeoutMillis maximum timeout
	 * @see #incrementTimeout(int, float, int)
	 * @since 3.0 (added scale and maxTimeoutMillis)
	 */
	public void incrementTimeout(float scale, int maxTimeoutMillis) {
		this.timeoutMillis = incrementTimeout(this.timeoutMillis, scale, maxTimeoutMillis);
	}

	/**
	 * Indicate, if flight needs retransmission.
	 * 
	 * @return {@code true}, if flight needs retransmission, {@code false},
	 *         otherwise.
	 */
	public boolean isRetransmissionNeeded() {
		return retransmissionNeeded;
	}

	/**
	 * Set retransmission needs.
	 * 
	 * @param needsRetransmission {@code true}, if flight needs retransmission,
	 *            {@code false}, otherwise.
	 */
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
	 * {@link DtlsConfig#DTLS_USE_EARLY_STOP_RETRANSMISSION} is configured,
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
	 * {@link #scheduleRetransmission(ScheduledExecutorService, Runnable)}.
	 */
	public void setResponseCompleted() {
		responseCompleted = true;
		cancelTimeout();
	}

	/**
	 * Check, if retransmission was cancelled.
	 * 
	 * @return {@code true}, if retransmission was cancelled, {@code false},
	 *         otherwise.
	 */
	public boolean isResponseCompleted() {
		return responseCompleted;
	}

	/**
	 * Check, if this flight includes a {@link Finished} message.
	 * 
	 * @return {@code true}, if {@link Finished} message is included,
	 *         {@code false}, otherwise.
	 * @see #addDtlsMessage(int, DTLSMessage)
	 * @since 3.9
	 */
	public boolean isFinishedIncluded() {
		return finishedIncluded;
	}

	/**
	 * Schedule timeout or retransmission task.
	 * 
	 * @param timer timer to schedule task.
	 * @param task task to be scheduled executed
	 * @since 2.4
	 */
	public void scheduleRetransmission(ScheduledExecutorService timer, Runnable task) {
		if (!responseCompleted) {
			if (isRetransmissionNeeded()) {
				cancelTimeout();
				// schedule retransmission task
				try {
					timeoutTask = timer.schedule(task, timeoutMillis, TimeUnit.MILLISECONDS);
					LOGGER.trace("handshake flight to peer {}, retransmission {} ms.", peerToLog, timeoutMillis);
				} catch (RejectedExecutionException ex) {
					LOGGER.trace("handshake flight stopped by shutdown.");
				}
			} else {
				LOGGER.trace("handshake flight to peer {}, no retransmission!", peerToLog);
			}
		}
	}

	/**
	 * Increment the timeout, here we scale it, limited by the provided maximum.
	 * 
	 * @param timeoutMillis timeout in milliseconds
	 * @param scale scale factor
	 * @param maxTimeoutMillis maximum timeout in milliseconds
	 * @return scaled and limited timeout in milliseconds
	 * @see #incrementTimeout(float, int)
	 * @since 3.0 (added scale and maxTimeoutMillis)
	 */
	public static int incrementTimeout(int timeoutMillis, float scale, int maxTimeoutMillis) {
		if (timeoutMillis < maxTimeoutMillis) {
			timeoutMillis = Math.round(timeoutMillis * scale);
			timeoutMillis = Math.min(timeoutMillis, maxTimeoutMillis);
		}
		return timeoutMillis;
	}

	/**
	 * Dtls message and epoch.
	 * 
	 * @since 2.4
	 */
	private static class EpochMessage {

		/**
		 * Epoch of message.
		 */
		private final int epoch;
		/**
		 * Dtls message.
		 */
		private final DTLSMessage message;

		/**
		 * Create epoch message.
		 * 
		 * @param epoch epoch of message
		 * @param message dtls message
		 */
		private EpochMessage(int epoch, DTLSMessage message) {
			this.epoch = epoch;
			this.message = message;
		}
	}
}
