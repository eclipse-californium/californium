/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.TokenGenerator;
import org.eclipse.californium.core.network.stack.ReliabilityLayerParameters;
import org.eclipse.californium.core.observe.ObserveManager;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextUtil;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
	/**
	 * The logger.
	 * 
	 * @deprecated scope will change to private
	 */
	@Deprecated
	protected final static Logger LOGGER = LoggerFactory.getLogger(Message.class);

	/**
	 * Offload mode.
	 * 
	 * @since 2.2
	 */
	public enum OffloadMode {
		/**
		 * Offload payload.
		 */
		PAYLOAD,
		/**
		 * Offload payload, options, serialized bytes.
		 */
		FULL
	}

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
	private byte[] payload = Bytes.EMPTY;

	/** Marks this message to have payload even if this is not intended */
	private boolean unintendedPayload;

	/**
	 * Maximum resource body size. For outgoing requests, this limits the size
	 * of the response.
	 * 
	 * @since 2.3
	 */
	private int maxResourceBodySize;

	/**
	 * Message specific parameter. Overwrites then general ones from
	 * {@link Configuration}.
	 */
	private volatile ReliabilityLayerParameters parameters;

	/**
	 * Destination endpoint context. Used for outgoing messages.
	 */
	private volatile EndpointContext destinationContext;
	/**
	 * Effective destination endpoint context. May differ from
	 * {@link #destinationContext} on retransmissions.
	 * 
	 * @see EndpointContextUtil#getFollowUpEndpointContext(EndpointContext,
	 *      EndpointContext)
	 * @since 2.3
	 */
	private volatile EndpointContext effectiveDestinationContext;

	/**
	 * Source endpoint context. Used for incoming messages.
	 */
	private volatile EndpointContext sourceContext;

	/**
	 * Local address of received messages.
	 * 
	 * @since 3.0
	 */
	private InetSocketAddress localAddress;

	/** Indicates, if the message has sent. */
	private volatile boolean sent;

	/** Indicates, if the message has been acknowledged. */
	private final AtomicBoolean acknowledged = new AtomicBoolean();

	/** Indicates, if the message has been rejected. */
	private volatile boolean rejected;

	/** Indicates, if the message has been canceled. */
	private volatile boolean canceled;

	/** Indicates, if the message has timed out */
	private volatile boolean timedOut; // Important for CONs

	/** Indicates, if the message is a duplicate. */
	private volatile boolean duplicate;

	/**
	 * Indicates, if the message-transfer is complete.
	 * 
	 * @since 3.0
	 */
	private volatile boolean transferComplete;

	/** Indicates, if sending the message caused an error. */
	private volatile Throwable sendError;

	/** The serialized message as byte array. Not available for blockwise transfer! */
	private volatile byte[] bytes;

	/** The serialized message size */
	private volatile int messageSize;

	/** Offload message. remove payload, options and serialized bytes to reduce heap usage, when message is kept for deduplication. */
	private volatile OffloadMode offload;

	/** Protect message from being offloaded. */
	private volatile boolean protectFromOffload;

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
	 * The nano-timestamp when this message has been received, sent, or
	 * {@code 0} if neither has happened yet.
	 */
	private volatile long nanoTimestamp;

	/**
	 * Creates a new message with no specified message type.
	 */
	protected Message() {
	}

	/**
	 * Get tracing string for message.
	 * 
	 * @param code code of message as text.
	 * @return tracing string for message
	 * @since 2.2
	 */
	protected String toTracingString(String code) {
		String status = getStatusTracingString();
		OffloadMode offload;
		OptionSet options;
		String payload = getPayloadTracingString();
		synchronized (acknowledged) {
			offload = this.offload;
			options = this.options;
		}
		if (offload == OffloadMode.FULL) {
			return String.format("%s-%-6s MID=%5d, Token=%s %s(offloaded!)", getType(), code, getMID(),
					getTokenString(), status);
		} else if (offload == OffloadMode.PAYLOAD) {
			return String.format("%s-%-6s MID=%5d, Token=%s, OptionSet=%s, %s(offloaded!)", getType(), code, getMID(),
					getTokenString(), options, status);
		} else {
			return String.format("%s-%-6s MID=%5d, Token=%s, OptionSet=%s, %s%s", getType(), code, getMID(),
					getTokenString(), options, status, payload);
		}
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
	 * Set message specific reliability layer parameters.
	 * 
	 * @param parameter message specific reliability layer parameters.
	 *            {@code null} to reset to default configuration.
	 */
	public void setReliabilityLayerParameters(ReliabilityLayerParameters parameter) {
		this.parameters = parameter;
	}

	/**
	 * Get message specific reliability layer parameters.
	 * 
	 * @return parameter message specific reliability layer parameters, or
	 *         {@code null}, if default configuration is to be used.
	 */
	public ReliabilityLayerParameters getReliabilityLayerParameters() {
		return parameters;
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
	 * Provides a fluent API to chain setters.
	 *
	 * @param mid the new mid
	 * @return this Message
	 * @throws IllegalArgumentException if mid is out of range {@link #NONE} to
	 *             {@link #MAX_MID}
	 * @throws IllegalStateException if message is already serialized
	 *             ({@link #setBytes(byte[])} has been called before)
	 */
	public Message setMID(int mid) {
		// NONE is allowed as a temporary placeholder
		if (mid > MAX_MID || mid < NONE) {
			throw new IllegalArgumentException("The MID must be an unsigned 16-bit number but was " + mid);
		}
		if (bytes != null) {
			throw new IllegalStateException("already serialized!");
		}
		this.mid = mid;
		return this;
	}

	/**
	 * Clears this message's MID.
	 * 
	 * @throws IllegalStateException if message is already serialized
	 *             ({@link #setBytes(byte[])} has been called before)
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
	 * Note: The token are generated by default with a {@link TokenGenerator}.
	 * If application defined tokens are to be used, these tokens must also
	 * comply to the scope encoding of the effectively used generator. This
	 * narrows the definition of RFC 7252, 5.3.1, from "client-local" to
	 * "node-local", and "system-local" tokens.
	 * 
	 * Provides a fluent API to chain setters.
	 *
	 * @param tokenBytes the new token bytes
	 * @return this Message
	 * @see #setToken(Token)
	 * @throws IllegalStateException if message is already serialized
	 *             ({@link #setBytes(byte[])} has been called before)
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
	 * Note: The token are generated by default with a {@link TokenGenerator}.
	 * If application defined tokens are to be used, these tokens must also
	 * comply to the scope encoding of the effectively used generator. This
	 * narrows the definition of RFC 7252, 5.3.1, from "client-local" to
	 * "node-local", and "system-local" tokens.
	 * 
	 * Provides a fluent API to chain setters.
	 *
	 * @param token the new token
	 * @return this Message
	 * @throws IllegalStateException if message is already serialized
	 *             ({@link #setBytes(byte[])} has been called before)
	 */
	public Message setToken(Token token) {
		this.token = token;
		if (bytes != null) {
			throw new IllegalStateException("already serialized!");
		}
		return this;
	}

	/**
	 * Gets the set of options. If no set has been defined yet, it creates a new
	 * one. EmptyMessages should not have any options.
	 * 
	 * @return the options
	 * @throws IllegalStateException if message was {@link #offload}ed.
	 */
	public OptionSet getOptions() {
		synchronized (acknowledged) {
			if (offload == OffloadMode.FULL) {
				throw new IllegalStateException("message " + offload + " offloaded! " + this);
			}
			if (options == null) {
				options = new OptionSet();
			}
			return options;
		}
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
	 * Get the maximum resource body size.
	 * 
	 * For incoming messages the protocol stack may set individual sizes. For
	 * outgoing requests, this limits the size of the response.
	 * 
	 * @return maximum resource body size. {@code 0} to use the
	 *         {@link Configuration} value of
	 *         {@link CoapConfig#MAX_RESOURCE_BODY_SIZE}.
	 * @since 2.3
	 */
	public int getMaxResourceBodySize() {
		return maxResourceBodySize;
	}

	/**
	 * Set the maximum resource body size.
	 * 
	 * For incoming messages the protocol stack may set individual sizes. For
	 * outgoing requests, this limits the size of the response.
	 * 
	 * @param maxResourceBodySize maximum resource body size. {@code 0} or
	 *            default is defined by the {@link Configuration} value of
	 *            {@link CoapConfig#MAX_RESOURCE_BODY_SIZE}.
	 * @since 2.3
	 */
	public void setMaxResourceBodySize(int maxResourceBodySize) {
		this.maxResourceBodySize = maxResourceBodySize;
	}

	/**
	 * Gets the size (amount of bytes) of the payload. Be aware that this might
	 * differ from the payload string length due to the UTF-8 encoding.
	 *
	 * @return the payload size
	 */
	public int getPayloadSize() {
		return payload.length;
	}

	/**
	 * Gets the raw payload.
	 *
	 * @return the payload.
	 * @throws IllegalStateException if message was {@link #offload}ed.
	 */
	public byte[] getPayload() {
		if (offload != null) {
			throw new IllegalStateException("message " + offload + " offloaded!");
		}
		return payload;
	}

	/**
	 * Gets the payload in the form of a string. Returns an empty string if no
	 * payload is defined.
	 * 
	 * @return the payload as string
	 * @throws IllegalStateException if message was {@link #offload}ed.
	 */
	public String getPayloadString() {
		if (offload != null) {
			throw new IllegalStateException("message " + offload + " offloaded!");
		}
		if (payload.length == 0) {
			return "";
		} else {
			return new String(payload, CoAP.UTF8_CHARSET);
		}
	}

	protected String getPayloadTracingString() {
		return StringUtil.toDisplayString(payload, 32);
	}

	/**
	 * Sets the UTF-8 bytes from the specified string as payload.
	 * 
	 * Provides a fluent API to chain setters.
	 * 
	 * @param payload the payload as string. {@code null} is replaced by an
	 *            empty string. An empty string is not considered to be payload
	 *            and therefore not cause a IllegalArgumentException, if this
	 *            message must not have payload.
	 * @return this Message
	 * @throws IllegalArgumentException if this message must not have payload
	 * @see #isIntendedPayload()
	 * @see #isUnintendedPayload()
	 * @see #setUnintendedPayload()
	 */
	public Message setPayload(String payload) {
		if (payload == null || payload.isEmpty()) {
			this.payload = Bytes.EMPTY;
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
	 * @param payload the new payload. {@code null} is replaced by an empty
	 *            array. An empty array is not considered to be payload and
	 *            therefore not cause an IllegalArgumentException, if this
	 *            message must not have payload.
	 * @return this Message
	 * @throws IllegalArgumentException if this message must not have payload
	 * @see #isIntendedPayload()
	 * @see #isUnintendedPayload()
	 * @see #setUnintendedPayload()
	 */
	public Message setPayload(byte[] payload) {
		if (payload == null || payload.length == 0) {
			this.payload = Bytes.EMPTY;
		} else {
			if (!isIntendedPayload() && !isUnintendedPayload()) {
				throw new IllegalArgumentException("Message must not have payload!");
			}
			this.payload = payload;
		}
		return this;
	}

	/**
	 * Check, if the payload size matches the {@link BlockOption#getSize()}.
	 * 
	 * @throws IllegalStateException if the {@link BlockOption} is
	 *        provided but the payload exceeds that.
	 * @since 3.0
	 */
	public abstract void assertPayloadMatchsBlocksize();

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
	 * Get the effective destination context. May differ from
	 * {@link #getDestinationContext()} on retransmissions.
	 * 
	 * @return the effective destination context.
	 * @see EndpointContextUtil#getFollowUpEndpointContext(EndpointContext,
	 *      EndpointContext)
	 * @since 2.3
	 */
	public EndpointContext getEffectiveDestinationContext() {
		return effectiveDestinationContext;
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
	 * Multicast addresses are only supported for {@link Request}s.
	 * 
	 * Provides a fluent API to chain setters.
	 * 
	 * @param peerContext destination endpoint context
	 * @return this Message
	 * @throws IllegalArgumentException if destination address is multicast
	 *             address, but message is no {@link Request}
	 * @see #setRequestDestinationContext(EndpointContext)
	 */
	public Message setDestinationContext(EndpointContext peerContext) {
		// requests calls setRequestDestinationContext instead
		if (peerContext != null) {
			InetAddress address = peerContext.getPeerAddress().getAddress();
			if (NetworkInterfacesUtil.isBroadcastAddress(address)) {
				throw new IllegalArgumentException(
						"Broadcast destination " + StringUtil.toString(address) + " only supported for request!");
			} else if (NetworkInterfacesUtil.isMultiAddress(address)) {
				throw new IllegalArgumentException(
						"Multicast destination " + StringUtil.toString(address) + " only supported for request!");
			}
		}
		this.destinationContext = peerContext;
		this.effectiveDestinationContext = peerContext;
		return this;
	}

	/**
	 * Set the effective destination context. Used to set a different
	 * destination context for retransmissions.
	 * 
	 * @param peerContext destination context for retransmissions
	 * @see EndpointContextUtil#getFollowUpEndpointContext(EndpointContext,
	 *      EndpointContext)
	 * @since 2.3
	 */
	public void setEffectiveDestinationContext(EndpointContext peerContext) {
		this.effectiveDestinationContext = peerContext;
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
		this.effectiveDestinationContext = peerContext;
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
	 * Set address of the receiving local endpoint.
	 * 
	 * @param local local address of the receiving endpoint
	 * @since 3.0
	 */
	public void setLocalAddress(InetSocketAddress local) {
		this.localAddress = local;
	}

	/**
	 * Gets the local address of the receiving endpoint.
	 * 
	 * @return local address of the receiving endpoint. {@code null} for
	 *         outgoing messages.
	 * @since 3.0
	 */
	public InetSocketAddress getLocalAddress() {
		return localAddress;
	}

	/**
	 * Checks if is this message has been acknowledged.
	 *
	 * @return true, if is acknowledged
	 */
	public boolean isAcknowledged() {
		return acknowledged.get();
	}

	/**
	 * Marks this message as acknowledged.
	 *
	 * Since 3.0 doesn't longer call
	 * {@link MessageObserver#onAcknowledgement()}. Use {@link #acknowledge()}
	 * instead.
	 * 
	 * Not part of the fluent API.
	 *
	 * @param acknowledged if acknowledged
	 */
	public void setAcknowledged(boolean acknowledged) {
		this.acknowledged.set(acknowledged);
	}

	/**
	 * Acknowledge a unacknowledged confirmable message.
	 *
	 * Checks and set {@link #acknowledged} atomically. Calls
	 * {@link MessageObserver#onAcknowledgement()}, if message was
	 * unacknowledged.
	 * 
	 * Not part of the fluent API.
	 *
	 * @return {@code true}, if message was unacknowledged and confirmable,
	 *         {@code false}, if message was already acknowledged or is not
	 *         confirmable
	 * @since 3.0 (doesn't longer call {@link #setAcknowledged(boolean)})
	 */
	public boolean acknowledge() {
		if (isConfirmable() && acknowledged.compareAndSet(false, true)) {
			for (MessageObserver handler : getMessageObservers()) {
				handler.onAcknowledgement();
			}
			return true;
		}
		return false;
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
	 * timeout.
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
		boolean retransmission = this.sent;
		this.sent = sent;
		if (sent) {
			for (MessageObserver handler : getMessageObservers()) {
				handler.onSent(retransmission);
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

	/**
	 * Report completion of message-transfer.
	 * 
	 * @since 3.0 (was onComplete())
	 */
	public void onTransferComplete() {
		if (!transferComplete) {
			transferComplete = true;
			LOGGER.trace("Message transfer completed {}", this);
			for (MessageObserver handler : getMessageObservers()) {
				handler.onTransferComplete();
			}
		}
	}

	/**
	 * Waits for the message to be sent.
	 * <p>
	 * This function blocks until the message is sent, has been canceled, the
	 * specified timeout has expired, or an error occurred. A timeout of 0 is
	 * interpreted as infinity. If the message is already sent, this method
	 * returns it immediately.
	 * <p>
	 * 
	 * @param timeout the maximum time to wait in milliseconds.
	 * @return {@code true}, if the message was sent in time, {@code false},
	 *         otherwise
	 * @throws InterruptedException the interrupted exception
	 */
	public boolean waitForSent(long timeout) throws InterruptedException {
		long expiresNano = ClockUtil.nanoRealtime() + TimeUnit.MILLISECONDS.toNanos(timeout);
		long leftTimeout = timeout;
		synchronized (this) {
			while (!sent && !isCanceled() && !isTimedOut() && getSendError() == null) {
				wait(leftTimeout);
				// timeout expired?
				if (timeout > 0) {
					long leftNanos = expiresNano - ClockUtil.nanoRealtime();
					if (leftNanos <= 0) {
						// break loop
						break;
					}
					// add 1 millisecond to prevent last wait with 0!
					leftTimeout = TimeUnit.NANOSECONDS.toMillis(leftNanos) + 1;
				}
			}
			return sent;
		}
	}

	/**
	 * Checks if this message is a duplicate.
	 * 
	 * Since 2.1 this also reflects, if the message is resent.
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

	protected String getStatusTracingString() {
		if (canceled) {
			return "canceled ";
		} else if (sendError != null) {
			return sendError.getMessage() + " ";
		} else if (rejected) {
			return "rejected ";
		} else if (acknowledged.get()) {
			return "acked ";
		} else if (timedOut) {
			return "timeout ";
		}
		return "";
	}

	/**
	 * Gets the serialized message as byte array or {@code null}, if not serialized yet.
	 *
	 * @return the bytes of the serialized message or {@code null}
	 * @throws IllegalStateException if message was {@link #offload}ed.
	 */
	public byte[] getBytes() {
		if (offload == OffloadMode.FULL) {
			throw new IllegalStateException("message offloaded!");
		}
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
		this.messageSize = bytes == null ? 0 : bytes.length;
	}

	/**
	 * Add bytes to message size.
	 * 
	 * Not part of the fluent API.
	 * 
	 * @param bytes bytes to add
	 * @since 3.7
	 */
	public void addMessageSize(int bytes) {
		this.messageSize += bytes;
	}

	/**
	 * Get message size.
	 * 
	 * For incoming blockwise transfer the accumulated message size is returned.
	 * 
	 * Not part of the fluent API.
	 * 
	 * @return message size
	 * @since 3.7
	 */
	public int getMessageSize() {
		return messageSize;
	}

	/**
	 * Checks whether a given block offset falls into this message's payload.
	 * 
	 * Note: since 3.0 the block option of the message is also used for the
	 * check. If this message exactly ends at the offset of the provided block,
	 * this is also reported as overlapping.
	 * 
	 * @param block The offset of the block.
	 * @return {@code true} if this message has a payload and its size is
	 *         greater then the offset.
	 */
	public abstract boolean hasBlock(final BlockOption block);

	/**
	 * Checks whether a given block offset falls into this message's payload.
	 * 
	 * @param block The offset of the block.
	 * @param messageOffset The offset of the payload within the resource-body.
	 * @return {@code true} if this message has a payload and its size is
	 *         greater then the offset.
	 * @since 3.0
	 */
	protected boolean hasBlock(BlockOption block, BlockOption messageOffset) {
		int offset = block.getOffset();
		if (messageOffset != null) {
			offset -= messageOffset.getOffset();
		}
		return 0 <= offset && offset <= getPayloadSize();
	}

	/**
	 * Gets the nano timestamp, when this message has been received, sent, or
	 * {@code 0}, if neither has happened yet. The sent timestamp is granted to
	 * be not after sending, therefore it's very short before actual sending the
	 * message. And the receive timestamp is granted to be not before receiving
	 * the message, therefore it's very short after actual receiving the
	 * message.
	 * 
	 * If a "transparent blockwise-transfers" is received, the time reflects the
	 * time of the first block.
	 * 
	 * @return the nano timestamp
	 * @see ClockUtil#nanoRealtime()
	 */
	public long getNanoTimestamp() {
		return nanoTimestamp;
	}

	/**
	 * Sets the nano timestamp when this message has been received, sent, or
	 * {@code 0} if neither has happened yet.
	 * 
	 * Not part of the fluent API.
	 *
	 * @param timestamp the nano timestamp.
	 * @see ClockUtil#nanoRealtime()
	 */
	public void setNanoTimestamp(long timestamp) {
		this.nanoTimestamp = timestamp;
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
	 * Offload message. Remove payload, options and serialized bytes to reduce
	 * heap usage, when message is kept for deduplication.
	 * 
	 * The server-side offloads message when sending the first response when
	 * {@link CoapConfig#USE_MESSAGE_OFFLOADING} is enabled. Requests are
	 * {@link OffloadMode#FULL} offloaded, responses are
	 * {@link OffloadMode#PAYLOAD} offloaded.
	 * 
	 * A client-side may also chose to offload requests and responses based on
	 * {@link CoapConfig#USE_MESSAGE_OFFLOADING}, when the request and responses are
	 * not longer used by the client.
	 * 
	 * For messages with {@link #setProtectFromOffload()}, offloading is
	 * ineffective.
	 * 
	 * @param mode {@link OffloadMode#PAYLOAD} to offload the payload,
	 *            {@link OffloadMode#FULL} to offload the payload, the options,
	 *            and the serialized bytes.
	 * @since 2.2
	 */
	public void offload(OffloadMode mode) {
		if (!protectFromOffload) {
			synchronized (acknowledged) {
				offload = mode;
				if (mode != null) {
					payload = Bytes.EMPTY;
					if (mode == OffloadMode.FULL) {
						bytes = null;
						if (options != null) {
							options.clear();
							options = null;
						}
					}
				}
			}
		}
	}

	/**
	 * Gets the offload mode.
	 * 
	 * @return {@code null}, if message is not offloaded,
	 *         {@link OffloadMode#PAYLOAD} if the payload is offloaded,
	 *         {@link OffloadMode#FULL} if the payload, the options, and the
	 *         serialized bytes are offloaded.
	 * @since 2.2
	 */
	public OffloadMode getOffloadMode() {
		return offload;
	}

	/**
	 * Protect message from being offloaded.
	 * 
	 * Used to protect observe- and starting-blockwise-requests and empty
	 * messages from being offloaded.
	 * @since 2.2
	 */
	public void setProtectFromOffload() {
		protectFromOffload = true;
	}

	/**
	 * Returns the observers registered for this message.
	 * 
	 * @return an immutable list of the registered observers.
	 * @see #getMessageObserver(Class)
	 * @see #addMessageObserver(MessageObserver)
	 * @see #addMessageObserver(int, MessageObserver)
	 * @see #addMessageObservers(List)
	 * @see #removeMessageObserver(MessageObserver)
	 */
	public List<MessageObserver> getMessageObservers() {
		if (null == unmodifiableMessageObserversFacade) {
			return Collections.emptyList();
		} else {
			return unmodifiableMessageObserversFacade;
		}
	}

	/**
	 * Returns the observer of the provided type registered for this message.
	 * 
	 * @param <T> type of observer
	 * @param type type of observer
	 * @return the registered observer of that type, or {@code null}, if not
	 *         available.
	 * @see #getMessageObservers()
	 * @see #addMessageObserver(MessageObserver)
	 * @see #addMessageObserver(int, MessageObserver)
	 * @see #addMessageObservers(List)
	 * @see #removeMessageObserver(MessageObserver)
	 * @since 3.3
	 */
	@SuppressWarnings("unchecked")
	public <T extends MessageObserver> T getMessageObserver(Class<T> type) {
		List<MessageObserver> list = unmodifiableMessageObserversFacade;
		if (null != list) {
			for (MessageObserver obs : list) {
				if (type.isInstance(obs)) {
					return (T) obs;
				}
			}
		}
		return null;
	}

	/**
	 * Adds the specified message observer.
	 *
	 * @param observer the observer
	 * @throws NullPointerException if the observer is {@code null}.
	 * @see #getMessageObservers()
	 * @see #addMessageObserver(int, MessageObserver)
	 * @see #addMessageObservers(List)
	 * @see #removeMessageObserver(MessageObserver)
	 */
	public void addMessageObserver(MessageObserver observer) {
		if (observer == null) {
			throw new NullPointerException();
		}
		ensureMessageObserverList().add(observer);
	}

	/**
	 * Adds the specified message observer.
	 *
	 * @param observer the observer
	 * @param index index at which the observer is to be inserted
	 * @throws NullPointerException if the observer is {@code null}.
	 * @see #getMessageObservers()
	 * @see #addMessageObserver(MessageObserver)
	 * @see #addMessageObservers(List)
	 * @see #removeMessageObserver(MessageObserver)
	 * @since 2.1
	 */
	public void addMessageObserver(int index, MessageObserver observer) {
		if (observer == null) {
			throw new NullPointerException();
		}
		ensureMessageObserverList().add(index, observer);
	}

	/**
	 * Appends a list of observers to this message's existing observers.
	 *
	 * @param observers the observers to add
	 * @throws NullPointerException if the list is {@code null}.
	 * @see #getMessageObservers()
	 * @see #addMessageObserver(MessageObserver)
	 * @see #addMessageObserver(int, MessageObserver)
	 * @see #removeMessageObserver(MessageObserver)
	 */
	public void addMessageObservers(List<MessageObserver> observers) {
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
	 * @see #getMessageObservers()
	 * @see #addMessageObserver(MessageObserver)
	 * @see #addMessageObserver(int, MessageObserver)
	 * @see #addMessageObservers(List)
	 */
	public void removeMessageObserver(MessageObserver observer) {
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
	 * 
	 * @return list of {@link MessageObserver}
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
