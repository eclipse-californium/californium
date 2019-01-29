/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add getPayloadTracingString 
 *                                                    (for message tracing)
 *    Achim Kraus (Bosch Software Innovations GmbH) - apply source formatter
 *    Achim Kraus (Bosch Software Innovations GmbH) - make messaging states thread safe
 *    Achim Kraus (Bosch Software Innovations GmbH) - add sent and sendError
 *                                                    issue #305
 *    Achim Kraus (Bosch Software Innovations GmbH) - use unmodifiable facade
 *                                                    instead of create it on
 *                                                    every getMessageObservers()
 *    Achim Kraus (Bosch Software Innovations GmbH) - make more messaging states thread
 *                                                    safe (add volatile)
 *    Achim Kraus (Bosch Software Innovations GmbH) - add setReadyToSend() to fix rare
 *                                                    race condition in block1wise
 *                                                    when the generated token was 
 *                                                    copied too late (after sending). 
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce source and destination
 *                                                    EndpointContext
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 *    Achim Kraus (Bosch Software Innovations GmbH) - move onContextEstablished
 *                                                    to MessageObserver.
 *                                                    Issue #487
 *    Achim Kraus (Bosch Software Innovations GmbH) - add onConnect
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix openjdk-11 covariant return types
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import java.net.InetAddress;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.observe.ObserveManager;
import org.eclipse.californium.elements.EndpointContext;

/**
 * The class Message models the base class of all CoAP messages. CoAP messages
 * are of type {@link Request}, {@link Response} or {@link EmptyMessage}. Each
 * message has a {@link Type}, a message identifier (MID), a token (0-8 bytes),
 * a collection of options ({@link OptionSet}) and a payload.
 * <p>
 * Furthermore, a message can be acknowledged, rejected, canceled, or time out;
 * the meaning of which is defined more specifically in the subclasses. Clients
 * can register {@link MessageObserver}s with a message which will be notified
 * when any of the events listed above occur.
 * <p>
 * Note: The {@link #messageObservers} and {@link #options} properties are
 * initialized lazily. This saves a few bytes in case the properties are not in
 * use. For instance an empty message should not have any options and most
 * messages will not have any observers registered.
 * 
 * @see Request
 * @see Response
 * @see EmptyMessage
 */
public abstract class Message {

	protected final static Logger LOGGER = LoggerFactory.getLogger(Message.class.getCanonicalName());

	/** The Constant NONE in case no MID has been set. */
	public static final int NONE = -1;
	/**
	 * The largest message ID allowed by CoAP.
	 * <p>
	 * The value of this constant is 2^16 - 1.
	 */
	public static final int MAX_MID = (1 << 16) - 1;

	/** The type. One of {CON, NON, ACK or RST}. */
	private CoAP.Type type;

	/** The 16-bit Message Identification. */
	private volatile int mid = NONE; // Message ID

	/**
	 * The token, a 0-8 byte array.
	 * <p>
	 * This field is initialized to {@code null} so that client code can
	 * determine whether the message already has a token assigned or not. An
	 * empty array would not work here because it is already a valid token
	 * according to the CoAP spec.
	 */
	private volatile Token token = null;

	/** The set of options of this message. */
	private OptionSet options;

	/** The payload of this message. */
	private byte[] payload;

	/** Marks this message to have payload even if this is not intended */
	private boolean unintendedPayload;

	/**
	 * Destination endpoint context. Used for outgoing messages.
	 */
	private volatile EndpointContext destinationContext;

	/**
	 * Source endpoint context. Used for incoming messages.
	 */
	private volatile EndpointContext sourceContext;

	/** Indicates if the message has sent. */
	private volatile boolean sent;

	/** Indicates if the message has been acknowledged. */
	private volatile boolean acknowledged;

	/** Indicates if the message has been rejected. */
	private volatile boolean rejected;

	/** Indicates if the message has been canceled. */
	private volatile boolean canceled;

	/** Indicates if the message has timed out */
	private volatile boolean timedOut; // Important for CONs

	/** Indicates if the message is a duplicate. */
	private volatile boolean duplicate;

	/** Indicates if sending the message caused an error. */
	private volatile Throwable sendError;

	/** The serialized message as byte array. */
	private volatile byte[] bytes;

	/**
	 * A list of all {@link ObserveManager} that should be notified when an
	 * event for this message occurs. By default, this field is null
	 * (lazy-initialization). If a handler is added, the list will be created
	 * and from then on must never again become null.
	 */
	private final AtomicReference<List<MessageObserver>> messageObservers = new AtomicReference<List<MessageObserver>>();

	/**
	 * A unmodifiable facade for the list of all {@link ObserveManager}.
	 * 
	 * @see #messageObservers
	 * @see #getMessageObservers()
	 */
	private volatile List<MessageObserver> unmodifiableMessageObserversFacade = null;

	/**
	 * The timestamp when this message has been received, sent, or 0, if neither
	 * has happened yet. The {@link Matcher} sets the timestamp.
	 */
	private volatile long timestamp;

	/**
	 * Creates a new message with no specified message type.
	 */
	protected Message() {
	}

	/**
	 * Creates a new message of a given type.
	 * <p>
	 * The type must be one of CON, NON, ACK or RST.
	 * 
	 * @param type the type
	 */
	public Message(Type type) {
		this.type = type;
	}

	/**
	 * Gets the message type ({@link Type#CON}, {@link Type#NON},
	 * {@link Type#ACK} or {@link Type#RST}). If no type has been defined, the
	 * type is null.
	 * 
	 * @return the type
	 */
	public Type getType() {
		return type;
	}

	/**
	 * Sets the CoAP message type.
	 * 
	 * Provides a fluent API to chain setters.
	 *
	 * @param type the new type
	 * @return this Message
	 */
	public Message setType(CoAP.Type type) {
		this.type = type;
		return this;
	}

	/**
	 * Checks if this message is confirmable.
	 *
	 * @return true, if is confirmable
	 */
	public boolean isConfirmable() {
		return getType() == Type.CON;
	}

	/**
	 * Chooses between confirmable and non-confirmable message.
	 * 
	 * Pass true for CON, false for NON. Provides a fluent API to chain setters.
	 *
	 * @param con true for CON, false for NON
	 * @return this Message
	 */
	public Message setConfirmable(boolean con) {
		setType(con ? Type.CON : Type.NON);
		return this;
	}

	/**
	 * Gets the raw integer value of this message's <em>code</em>.
	 * 
	 * @return the code value.
	 */
	public abstract int getRawCode();

	/**
	 * Checks, if this message is intended to have payload.
	 * 
	 * To be overwritten by subclass to provide a specific check.
	 * 
	 * @return {@code true}, if message is intended to have payload
	 */
	public boolean isIntendedPayload() {
		return true;
	}

	/**
	 * Set marker for unintended payload.
	 * 
	 * Enables to use payload with messages, which are not intended to have
	 * payload.
	 * 
	 * @throws IllegalStateException if message is intended to have payload
	 */
	public void setUnintendedPayload() {
		if (isIntendedPayload()) {
			throw new IllegalStateException("Message is already intended to have payload!");
		}
		unintendedPayload = true;
	}

	/**
	 * Checks, if message is marked to have unintended payload.
	 * 
	 * @return {@code true} if message is marked to have unintended payload
	 */
	public boolean isUnintendedPayload() {
		return unintendedPayload;
	}

	/**
	 * Gets the 16-bit message identification.
	 *
	 * @return the mid
	 */
	public int getMID() {
		return mid;
	}

	/**
	 * Checks whether this message has a valid ID.
	 * 
	 * @return {@code true} if this message's ID is a 16 bit unsigned integer.
	 */
	public boolean hasMID() {
		return mid != NONE;
	}

	/**
	 * Sets the 16-bit message identification.
	 *
	 * Reset {@link #bytes} to force new serialization.
	 *
	 * Provides a fluent API to chain setters.
	 *
	 * @param mid the new mid
	 * @return this Message
	 */
	public Message setMID(int mid) {
		// NONE is allowed as a temporary placeholder
		if (mid > MAX_MID || mid < NONE) {
			throw new IllegalArgumentException("The MID must be an unsigned 16-bit number but was " + mid);
		}
		this.mid = mid;
		bytes = null;
		return this;
	}

	/**
	 * Clears this message's MID.
	 */
	public void removeMID() {
		setMID(NONE);
	}

	/**
	 * Checks whether this message has a non-zero length token.
	 * 
	 * @return {@code true} if this message's token is either {@code null} or of
	 *         length 0.
	 */
	public boolean hasEmptyToken() {
		return token == null || token.isEmpty();
	}

	/**
	 * Gets this message's token.
	 *
	 * @return the token
	 */
	public Token getToken() {
		return token;
	}

	/**
	 * Gets this message's 0- -8 byte token.
	 *
	 * @return the token
	 */
	public byte[] getTokenBytes() {
		return token == null ? null : token.getBytes();
	}

	/**
	 * Gets the 0--8 byte token as string representation.
	 *
	 * @return the token as string
	 */
	public String getTokenString() {
		return token == null ? "null" : token.getAsString();
	}

	/**
	 * Sets the token bytes, which can be 0--8 bytes.
	 * 
	 * Note: 
	 * To support address changes, the provided tokens must be unique for
	 * all clients and not only for the client the message is sent to. This
	 * narrows the definition of RFC 7252, 5.3.1, from "client-local" to
	 * "system-local".
	 * 
	 * Reset {@link #bytes} to force new serialization.
	 * 
	 * Provides a fluent API to chain setters.
	 *
	 * @param tokenBytes the new token bytes
	 * @return this Message
	 * @see #setToken(Token)
	 */
	public Message setToken(byte[] tokenBytes) {
		Token token = null;
		if (tokenBytes != null) {
			token = new Token(tokenBytes);
		}
		return setToken(token);
	}

	/**
	 * Sets the token.
	 * 
	 * Note: 
	 * To support address changes, the provided tokens must be unique for
	 * all clients and not only for the client the message is sent to. This
	 * narrows the definition of RFC 7252, 5.3.1, from "client-local" to
	 * "system-local".
	 * 
	 * Reset {@link #bytes} to force new serialization.
	 * 
	 * Provides a fluent API to chain setters.
	 *
	 * @param token the new token
	 * @return this Message
	 */
	public Message setToken(Token token) {
		this.token = token;
		bytes = null;
		return this;
	}

	/**
	 * Gets the set of options. If no set has been defined yet, it creates a new
	 * one. EmptyMessages should not have any options.
	 * 
	 * @return the options
	 */
	public OptionSet getOptions() {
		if (options == null) {
			options = new OptionSet();
		}
		return options;
	}

	/**
	 * Sets the set of options.
	 * 
	 * This function makes a defensive copy of the specified set of options.
	 * Provides a fluent API to chain setters.
	 * 
	 * @param options the new options
	 * @return this Message
	 */
	public Message setOptions(OptionSet options) {
		this.options = new OptionSet(options);
		return this;
	}

	/**
	 * Gets the size (amount of bytes) of the payload. Be aware that this might
	 * differ from the payload string length due to the UTF-8 encoding.
	 *
	 * @return the payload size
	 */
	public int getPayloadSize() {
		return payload == null ? 0 : payload.length;
	}

	/**
	 * Gets the raw payload.
	 *
	 * @return the payload
	 */
	public byte[] getPayload() {
		return payload;
	}

	/**
	 * Gets the payload in the form of a string. Returns an empty string if no
	 * payload is defined.
	 * 
	 * @return the payload as string
	 */
	public String getPayloadString() {
		if (payload == null) {
			return "";
		}
		return new String(payload, CoAP.UTF8_CHARSET);
	}

	protected String getPayloadTracingString() {

		if (null == payload || 0 == payload.length) {
			return "no payload";
		}
		boolean text = true;
		for (byte b : payload) {
			if (' ' > b) {
				switch (b) {
				case '\t':
				case '\n':
				case '\r':
					continue;
				}
				text = false;
				break;
			}
		}
		if (text) {
			CharsetDecoder decoder = CoAP.UTF8_CHARSET.newDecoder();
			decoder.onMalformedInput(CodingErrorAction.REPORT);
			decoder.onUnmappableCharacter(CodingErrorAction.REPORT);
			ByteBuffer in = ByteBuffer.wrap(payload);
			CharBuffer out = CharBuffer.allocate(24);
			CoderResult result = decoder.decode(in, out, true);
			decoder.flush(out);
			((Buffer)out).flip();
			if (CoderResult.OVERFLOW == result) {
				return "\"" + out + "\".. " + payload.length + " bytes";
			} else if (!result.isError()) {
				return "\"" + out + "\"";
			}
		}
		return Utils.toHexText(payload, 256);
	}

	/**
	 * Sets the UTF-8 bytes from the specified string as payload.
	 * 
	 * Provides a fluent API to chain setters.
	 * 
	 * @param payload the payload as string. {@code null} or a empty string are
	 *            not considered to be payload and therefore not cause a
	 *            IllegalArgumentException, if this message must not have
	 *            payload.
	 * @return this Message
	 * @throws IllegalArgumentException if this message must not have payload
	 * @see #isIntendedPayload()
	 * @see #isUnintendedPayload()
	 * @see #setUnintendedPayload()
	 */
	public Message setPayload(String payload) {
		if (payload == null) {
			this.payload = null;
		} else {
			setPayload(payload.getBytes(CoAP.UTF8_CHARSET));
		}
		return this;
	}

	/**
	 * Sets the payload.
	 *
	 * Provides a fluent API to chain setters.
	 *
	 * @param payload the new payload. {@code null} or a empty array are not
	 *            considered to be payload and therefore not cause a
	 *            IllegalArgumentException, if this message must not have
	 *            payload.
	 * @return this Message
	 * @throws IllegalArgumentException if this message must not have payload
	 * @see #isIntendedPayload()
	 * @see #isUnintendedPayload()
	 * @see #setUnintendedPayload()
	 */
	public Message setPayload(byte[] payload) {
		if (payload != null && payload.length > 0 && !isIntendedPayload() && !isUnintendedPayload()) {
			throw new IllegalArgumentException("Message must not have payload!");
		}
		this.payload = payload;
		return this;
	}

	/**
	 * Gets the destination address.
	 *
	 * @return the destination
	 * @deprecated use {@link #getDestinationContext()}
	 */
	public InetAddress getDestination() {
		EndpointContext destinationContext = this.destinationContext;
		if (destinationContext == null) {
			return null;
		}
		return destinationContext.getPeerAddress().getAddress();
	}

	/**
	 * Gets the destination port.
	 *
	 * @return the destination port
	 * @deprecated use {@link #getDestinationContext()}
	 */
	public int getDestinationPort() {
		EndpointContext destinationContext = this.destinationContext;
		if (destinationContext == null) {
			return -1;
		}
		return destinationContext.getPeerAddress().getPort();
	}

	/**
	 * Gets the source address.
	 *
	 * @return the source
	 * @deprecated use {@link #getSourceContext()}
	 */
	public InetAddress getSource() {
		EndpointContext sourceContext = this.sourceContext;
		if (sourceContext == null) {
			return null;
		}
		return sourceContext.getPeerAddress().getAddress();
	}

	/**
	 * Gets the source port.
	 *
	 * @return the source port
	 * @deprecated use {@link #getSourceContext()}
	 */
	public int getSourcePort() {
		EndpointContext sourceContext = this.sourceContext;
		if (sourceContext == null) {
			return -1;
		}
		return sourceContext.getPeerAddress().getPort();
	}

	/**
	 * Get destination endpoint context.
	 * 
	 * May be {@code null} for {@link Request} during it's construction.
	 * 
	 * @return the destination endpoint context.
	 */
	public EndpointContext getDestinationContext() {
		return destinationContext;
	}

	/**
	 * Get source endpoint context.
	 * 
	 * @return the source endpoint context.
	 */
	public EndpointContext getSourceContext() {
		return sourceContext;
	}

	/**
	 * Set destination endpoint context.
	 * 
	 * Multicast addresses are not supported.
	 * 
	 * Provides a fluent API to chain setters.
	 * 
	 * @param peerContext destination endpoint context
	 * @return this Message
	 * @throws IllegalArgumentException if destination address is multicast
	 *             address
	 * @see #setRequestDestinationContext(EndpointContext)
	 */
	public Message setDestinationContext(EndpointContext peerContext) {
		// requests calls setRequestDestinationContext instead
		if (peerContext != null && peerContext.getPeerAddress().getAddress().isMulticastAddress()) {
			throw new IllegalArgumentException("Multicast destination is only supported for request!");
		}
		this.destinationContext = peerContext;
		return this;
	}

	/**
	 * Set destination endpoint context for requests.
	 * Multicast addresses are supported.
	 * 
	 * @param peerContext destination endpoint context
	 * @see #setDestinationContext(EndpointContext)
	 */
	protected void setRequestDestinationContext(EndpointContext peerContext) {
		this.destinationContext = peerContext;
	}

	/**
	 * Set source endpoint context.
	 * 
	 * Provides a fluent API to chain setters.
	 * 
	 * @param peerContext source endpoint context
	 * @return this Message
	 */
	public Message setSourceContext(EndpointContext peerContext) {
		this.sourceContext = peerContext;
		return this;
	}

	/**
	 * Checks if is this message has been acknowledged.
	 *
	 * @return true, if is acknowledged
	 */
	public boolean isAcknowledged() {
		return acknowledged;
	}

	/**
	 * Marks this message as acknowledged.
	 *
	 * Not part of the fluent API.
	 *
	 * @param acknowledged if acknowledged
	 */
	public void setAcknowledged(boolean acknowledged) {
		this.acknowledged = acknowledged;
		if (acknowledged) {
			for (MessageObserver handler : getMessageObservers()) {
				handler.onAcknowledgement();
			}
		}
	}

	/**
	 * Checks if this message has been rejected.
	 *
	 * @return true, if is rejected
	 */
	public boolean isRejected() {
		return rejected;
	}

	/**
	 * Marks this message as rejected.
	 *
	 * Not part of the fluent API.
	 *
	 * @param rejected if rejected
	 */
	public void setRejected(boolean rejected) {
		this.rejected = rejected;
		if (rejected) {
			for (MessageObserver handler : getMessageObservers()) {
				handler.onReject();
			}
		}
	}

	/**
	 * Checks if this message has timed out. Confirmable messages in particular
	 * might timeout.
	 * 
	 * @return true, if timed out
	 */
	public boolean isTimedOut() {
		return timedOut;
	}

	/**
	 * Marks this message as timed out. Confirmable messages in particular might
	 * time out.
	 * 
	 * @param timedOut {@code true} if timed out
	 */
	public void setTimedOut(final boolean timedOut) {
		this.timedOut = timedOut;
		if (timedOut) {
			for (MessageObserver observer : getMessageObservers()) {
				observer.onTimeout();
			}
		}
	}

	/**
	 * Checks if this message has been canceled.
	 * 
	 * @return true, if is canceled
	 */
	public boolean isCanceled() {
		return canceled;
	}

	/**
	 * Marks this message as canceled.
	 * 
	 * Not part of the fluent API.
	 * 
	 * @param canceled if canceled
	 */
	public void setCanceled(boolean canceled) {
		this.canceled = canceled;
		if (canceled) {
			for (MessageObserver handler : getMessageObservers()) {
				handler.onCancel();
			}
		}
	}

	/**
	 * Indicate, that this message is ready to be send.
	 * 
	 * Not part of the fluent API.
	 */
	public void setReadyToSend() {
		for (MessageObserver handler : getMessageObservers()) {
			handler.onReadyToSend();
		}
	}

	/**
	 * Indicate, that this message triggered the connector to establish a
	 * connection. Not part of the fluent API.
	 */
	public void onConnecting() {
		for (MessageObserver handler : getMessageObservers()) {
			handler.onConnecting();
		}
	}

	/**
	 * Indicate, that this message triggered the connector to establish a
	 * connection and a dtls handshake flight was retransmitted.
	 * 
	 * @param flight {@code 1 ... 6}, number of retransmitted flight.
	 */
	public void onDtlsRetransmission(int flight) {
		for (MessageObserver handler : getMessageObservers()) {
			handler.onDtlsRetransmission(flight);
		}
	}

	/**
	 * Checks if this message has been sent.
	 * 
	 * @return true, if is sent
	 */
	public boolean isSent() {
		return sent;
	}

	/**
	 * Marks this message as sent.
	 * 
	 * Not part of the fluent API.
	 * 
	 * @param sent if sent
	 */
	public void setSent(boolean sent) {
		this.sent = sent;
		if (sent) {
			for (MessageObserver handler : getMessageObservers()) {
				handler.onSent();
			}
		}
	}

	/**
	 * Checks if this message has been sent.
	 * 
	 * @return true, if is sent
	 */
	public Throwable getSendError() {
		return sendError;
	}

	/**
	 * Marks this message with send error.
	 * 
	 * Not part of the fluent API.
	 * 
	 * @param sendError if error occurred while sending
	 */
	public void setSendError(Throwable sendError) {
		this.sendError = sendError;
		if (sendError != null) {
			for (MessageObserver handler : getMessageObservers()) {
				handler.onSendError(sendError);
			}
		}
	}

	/**
	 * Report resulting endpoint context.
	 * 
	 * The {@link #destinationContext} may not contain all information, but the
	 * connector will fill these information and report it. This method doesn't
	 * change the {@link #destinationContext} but calls
	 * {@link MessageObserver#onContextEstablished(EndpointContext)}.
	 * 
	 * @param endpointContext resulting endpoint context.
	 */
	public void onContextEstablished(EndpointContext endpointContext) {
		if (endpointContext != null) {
			for (MessageObserver handler : getMessageObservers()) {
				handler.onContextEstablished(endpointContext);
			}
		}
	}

	public void onComplete() {
		LOGGER.trace("Message completed {}", this);
		for (MessageObserver handler : getMessageObservers()) {
			handler.onComplete();
		}
	}

	/**
	 * Checks if this message is a duplicate.
	 *
	 * @return true, if is a duplicate
	 */
	public boolean isDuplicate() {
		return duplicate;
	}

	/**
	 * Marks this message as a duplicate.
	 * 
	 * Not part of the fluent API.
	 *
	 * @param duplicate if a duplicate
	 */
	public void setDuplicate(boolean duplicate) {
		this.duplicate = duplicate;
	}

	/**
	 * Gets the serialized message as byte array or null if not serialized yet.
	 *
	 * @return the bytes of the serialized message or null
	 */
	public byte[] getBytes() {
		return bytes;
	}

	/**
	 * Sets the bytes of the serialized message.
	 * 
	 * Not part of the fluent API.
	 *
	 * @param bytes the serialized bytes
	 */
	public void setBytes(byte[] bytes) {
		this.bytes = bytes;
	}

	/**
	 * Checks whether a given block offset falls into this message's payload.
	 * 
	 * @param block2 The offset of the block.
	 * @return {@code true} if this message has a payload and its size is
	 *         greater then the offset.
	 */
	public boolean hasBlock(final BlockOption block2) {

		return 0 < getPayloadSize() && block2.getOffset() < getPayloadSize();
	}

	/**
	 * Gets the timestamp.
	 *
	 * @return the timestamp
	 */
	public long getTimestamp() {
		return timestamp;
	}

	/**
	 * Sets the timestamp.
	 * 
	 * Not part of the fluent API.
	 *
	 * @param timestamp the new timestamp
	 */
	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}

	/**
	 * Cancels this message.
	 * 
	 * This method calls {@link #setCanceled(boolean)} with {@code true}.
	 * Subclasses should override {@link #setCanceled(boolean)} to react to
	 * cancellation.
	 */
	public void cancel() {
		setCanceled(true);
	}

	/**
	 * Notifies all registered {@code MessageObserver}s that this message is
	 * about to be re-transmitted.
	 */
	public void retransmitting() {
		for (MessageObserver observer : getMessageObservers()) {
			try {
				// guard against faulty MessageObservers
				observer.onRetransmission();
			} catch (Exception e) {
				LOGGER.error("Faulty MessageObserver for retransmitting events", e);
			}
		}
	}

	/**
	 * Returns the observers registered for this message.
	 * 
	 * @return an immutable list of the registered observers.
	 */
	public List<MessageObserver> getMessageObservers() {
		if (null == unmodifiableMessageObserversFacade) {
			return Collections.emptyList();
		} else {
			return unmodifiableMessageObserversFacade;
		}
	}

	/**
	 * Adds the specified message observer.
	 *
	 * @param observer the observer
	 * @throws NullPointerException if the observer is {@code null}.
	 */
	public void addMessageObserver(final MessageObserver observer) {
		if (observer == null) {
			throw new NullPointerException();
		}
		ensureMessageObserverList().add(observer);
	}

	/**
	 * Appends a list of observers to this message's existing observers.
	 *
	 * @param observers the observers to add
	 * @throws NullPointerException if the list is {@code null}.
	 */
	public void addMessageObservers(final List<MessageObserver> observers) {
		if (observers == null) {
			throw new NullPointerException();
		}
		if (!observers.isEmpty()) {
			ensureMessageObserverList().addAll(observers);
		}
	}

	/**
	 * Removes the specified message observer.
	 *
	 * @param observer the observer
	 * @throws NullPointerException if the observer is {@code null}.
	 */
	public void removeMessageObserver(final MessageObserver observer) {
		if (observer == null) {
			throw new NullPointerException();
		}
		List<MessageObserver> list = messageObservers.get();
		if (list != null) {
			list.remove(observer);
		}
	}

	/**
	 * Get list of {@link MessageObserver}. If not already defined, create a new
	 * one. This method is thread-safe and creates exactly one list.
	 */
	private List<MessageObserver> ensureMessageObserverList() {
		List<MessageObserver> list = messageObservers.get();
		if (null == list) {
			boolean created = messageObservers.compareAndSet(null, new CopyOnWriteArrayList<MessageObserver>());
			list = messageObservers.get();
			if (created) {
				unmodifiableMessageObserversFacade = Collections.unmodifiableList(list);
			}
		}
		return list;
	}

}
