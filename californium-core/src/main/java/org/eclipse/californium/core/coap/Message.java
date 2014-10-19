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

import java.net.InetAddress;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.observe.ObserveManager;

/**
 * The class Message models the base class of all CoAP messages. CoAP messages
 * are of type {@link Request}, {@link Response} or {@link EmptyMessage}. Each
 * message has a {@link Type}, a message identifier (MID), a token (0-8 bytes),
 * a collection of options ({@link OptionSet}) and a payload.
 * <p>
 * Furthermore, a message can be acknowledged, rejected, canceled, or time out;
 * the meaning of which is defined more specifically in the subclasses. A
 * message can be observed by {@link MessageObserver} which will be notified
 * when an event triggers one of the properties from above become true.
 * <p>
 * Note: The variables {@link #handlers} and {@link #options} are
 * lazy-initialized. This saves a few bytes in case it the variables are not in
 * use. For instance an empty message should not have options and most messages
 * will not have a {@link MessageObserver} registered.
 * @see Request
 * @see Response
 * @see EmptyMessage
 */
public abstract class Message {
	
	protected final static Logger LOGGER = Logger.getLogger(Message.class.getCanonicalName());
	
	/** The Constant NONE in case no MID has been set. */
	public static final int NONE = -1;
	
	/** The type. One of {CON, NON, ACK or RST}. */
	private CoAP.Type type;

	/** The 16-bit Message Identification. */
	private int mid = NONE; // Message ID
	
	/** The token, a 0-8 byte array. */
	private byte[] token;
	
	/** The set of options of this message. */
	private OptionSet options;
	
	/** The payload of this message. */
	private byte[] payload;
	
	/** The payload as string. */
	private String payloadString; // lazy-initialized.
	
	/** The destination address of this message. */
	private InetAddress destination;
	
	/** The source address of this message. */
	private InetAddress source;
	
	/** The destination port of this message. */
	private int destinationPort;
	
	/** The source port of this message. */
	private int sourcePort;
	
	/** Indicates if the message has been acknowledged. */
	private boolean acknowledged;
	
	/** Indicates if the message has been rejected. */
	private boolean rejected;
	
	/** Indicates if the message has been canceled. */
	private boolean canceled;
	
	/** Indicates if the message has timed out */
	private boolean timedOut; // Important for CONs
	
	/** Indicates if the message is a duplicate. */
	private boolean duplicate;
	
	/** The serialized message as byte array. */
	private byte[] bytes;
	
	/**
	 * A list of all {@link ObserveManager} that should be notified when an
	 * event for this message occurs. By default, this field is null
	 * (lazy-initialization). If a handler is added, the list will be created
	 * and from then on must never again become null.
	 */
	private List<MessageObserver> handlers = null;
	
	/**
	 * The timestamp when this message has been received or sent or 0 if neither
	 * has happened yet. The {@link Matcher} sets the timestamp.
	 */
	private long timestamp;
	
	/**
	 * Instantiates a new message with no specified message type.
	 */
	public Message() { }
	
	/**
	 * Instantiates a new message with the given type. The type must be one of
	 * CON, NON, ACK or RST.
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
	 * Sets the type.
	 *
	 * @param type the new type
	 */
	public void setType(CoAP.Type type) {
		this.type = type;
	}
	
	/**
	 * Checks if this message is confirmable.
	 *
	 * @return true, if is confirmable
	 */
	public boolean isConfirmable() {
		return getType()==Type.CON;
	}
	
	/**
	 * Makes this message a confirmable message with type CON.
	 *
	 * @param con the new confirmable
	 */
	public void setConfirmable(boolean con) {
		setType(con?Type.CON:Type.NON);
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
	 * Sets the 16-bit message identification.
	 *
	 * @param mid the new mid
	 */
	public void setMID(int mid) {
		if (mid >= 1<<16 || mid < NONE)
			throw new IllegalArgumentException("The MID must be a 16-bit number between 0 and "+((1<<16)-1)+" inclusive but was "+mid);
		this.mid = mid;
	}
	
	public void removeMID() {
		setMID(NONE);
	}
	
	/**
	 * Gets the 0-8 byte token.
	 *
	 * @return the token
	 */
	public byte[] getToken() {
		return token;
	}
	
	public boolean hasEmptyToken() {
		return token == null || token.length == 0;
	}
	
	public String getTokenString() {
		StringBuffer tok = new StringBuffer(getToken()==null?"null":"");
		if (getToken()!=null) for(byte b:getToken()) tok.append(String.format("%02x", b&0xff));
		return tok.toString();
	}

	/**
	 * Sets the 0-8 byte token.
	 *
	 * @param token the new token
	 */
	public void setToken(byte[] token) {
		if (token != null && token.length > 8)
			throw new IllegalArgumentException("Token length must be between 0 and 8 inclusive");
		this.token = token;
	}
	
	/**
	 * Gets the set of options. If no set has been defined yet, it creates a new
	 * one. EmptyMessages should not have any options.
	 * 
	 * @return the options
	 */
	public OptionSet getOptions() {
		if (options == null)
			options = new OptionSet();
		return options;
	}
	
	/**
	 * Sets the set of options. This function makes a defensive copy of the
	 * specified set of options.
	 * 
	 * @param options the new options
	 */
	public void setOptions(OptionSet options) {
		this.options = options;
	}
	
	/**
	 * Gets the payload.
	 *
	 * @return the payload
	 */
	public byte[] getPayload() {
		return payload;
	}
	
	/**
	 * Gets the payload in the form of a string. Returns null if no payload is
	 * defined.
	 * 
	 * @return the payload as string
	 */
	public String getPayloadString() {
		if (payload==null)
			return null;
		this.payloadString = new String(payload, CoAP.UTF8_CHARSET);
		return payloadString;
	}
	
	/**
	 * Gets the size (amount of bytes) of the payload.
	 *
	 * @return the payload size
	 */
	public int getPayloadSize() {
		return payload == null ? 0 : payload.length;
	}
	
	/**
	 * Sets the bytes from the specified string as payload. To clear the payload
	 * from a message, do not use null but an empty string.
	 * 
	 * @param payload the payload
	 * @throws NullPointerException if the payload is null
	 */
	public Message setPayload(String payload) {
		if (payload == null)
			throw new NullPointerException();
		setPayload(payload.getBytes(CoAP.UTF8_CHARSET));
		return this;
	}
	
	/**
	 * Sets the bytes from the specified string as payload and the specified
	 * media type. To clear the payload from a message, do not use null but an
	 * empty string.
	 * 
	 * @param payload the payload
	 * @param mediaType the Internet Media Type
	 * @throws NullPointerException if the payload is null
	 * @see MediaTypeRegistry
	 */
	public Message setPayload(String payload, int mediaType) {
		setPayload(payload);
		getOptions().setContentFormat(mediaType);
		return this;
	}
	
	/**
	 * Sets the payload.
	 *
	 * @param payload the new payload
	 */
	public Message setPayload(byte[] payload) {
		this.payload = payload;
		this.payloadString = null; // reset lazy-initialized variable
		return this;
	}

	/**
	 * Gets the destination address.
	 *
	 * @return the destination
	 */
	public InetAddress getDestination() {
		return destination;
	}

	/**
	 * Sets the destination address.
	 *
	 * @param destination the new destination
	 */
	public void setDestination(InetAddress destination) {
		this.destination = destination;
	}

	/**
	 * Gets the source address.
	 *
	 * @return the source
	 */
	public InetAddress getSource() {
		return source;
	}

	/**
	 * Sets the source address.
	 *
	 * @param source the new source
	 */
	public void setSource(InetAddress source) {
		this.source = source;
	}

	/**
	 * Gets the destination port.
	 *
	 * @return the destination port
	 */
	public int getDestinationPort() {
		return destinationPort;
	}

	/**
	 * Sets the destination port.
	 *
	 * @param destinationPort the new destination port
	 */
	public void setDestinationPort(int destinationPort) {
		this.destinationPort = destinationPort;
	}

	/**
	 * Gets the source port.
	 *
	 * @return the source port
	 */
	public int getSourcePort() {
		return sourcePort;
	}

	/**
	 * Sets the source port.
	 *
	 * @param sourcePort the new source port
	 */
	public void setSourcePort(int sourcePort) {
		this.sourcePort = sourcePort;
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
	 * @param acknowledged if acknowledged
	 */
	public void setAcknowledged(boolean acknowledged) {
		this.acknowledged = acknowledged;
		if (acknowledged)
			for (MessageObserver handler:getMessageObservers())
				handler.onAcknowledgement();
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
	 * @param rejected if rejected
	 */
	public void setRejected(boolean rejected) {
		this.rejected = rejected;
		if (rejected)
			for (MessageObserver handler:getMessageObservers())
				handler.onReject();
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
	 * @param timedOut true if timed out
	 */
	public void setTimedOut(boolean timedOut) {
		this.timedOut = timedOut;
		if (timedOut) {
			for (MessageObserver handler:getMessageObservers()) {
				handler.onTimeout();
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
	 * @param canceled if canceled
	 */
	public void setCanceled(boolean canceled) {
		this.canceled = canceled;
		if (canceled)
			for (MessageObserver handler:getMessageObservers())
				handler.onCancel();
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
	 * Marks this message as a duplicate
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
	 * @param bytes the serialized bytes
	 */
	public void setBytes(byte[] bytes) {
		this.bytes = bytes;
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
	 * @param timestamp the new timestamp
	 */
	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}

	/**
	 * Cancels this message. This method calls #setCanceled(true).
	 * Subclasses should override #setCanceled(boolean) to react to
	 * cancellation.
	 */
	public void cancel() {
		setCanceled(true);
	}
	
	public void retransmitting() {
			for (MessageObserver handler:getMessageObservers()) {
				try {
					// guard against faulty MessageObservers
					handler.onRetransmission();
				} catch (Exception e) {
					LOGGER.log(Level.SEVERE, "Faulty MessageObserver for retransmitting events.", e);
				}
			}
	}
	
    /**
	 * Returns an {@link Iterable} over the elements in this list in proper
	 * sequence.
	 * <p>
	 * The returned iterable provides an iterator over all
	 * {@link MessageObserver} registered with this message. No synchronization
	 * is needed while traversing the iterator. The method never returns null.
	 * The iterator does <em>NOT</em> support the <tt>remove</tt> method.
	 * 
	 * @return an iterable of all {@link MessageObserver} of this message
	 */
	public List<MessageObserver> getMessageObservers() {
		List<MessageObserver> handlers = this.handlers;
		if (handlers == null)
			return Collections.emptyList();
		else
			return handlers;
	}

	/**
	 * Adds the specified message observer.
	 *
	 * @param observer the observer
	 */
	public void addMessageObserver(MessageObserver observer) {
		if (observer == null)
			throw new NullPointerException();
		if (handlers == null)
			createMessageObserver();
		handlers.add(observer);
	}
	
	/**
	 * Removes the specified message observer.
	 *
	 * @param observer the observer
	 */
	public void removeMessageObserver(MessageObserver observer) {
		if (observer == null)
			throw new NullPointerException();
		if (handlers == null) return;
		handlers.remove(observer);
	}
	
	/**
	 * Create a new list of {@link MessageObserver} if not already defined. This
	 * method is thread-safe and creates exactly one list.
	 */
	private void createMessageObserver() {
		if (handlers == null) {
			synchronized (this) {
				if (handlers == null) 
					handlers = new CopyOnWriteArrayList<MessageObserver>();
			}
		}
	}

}
