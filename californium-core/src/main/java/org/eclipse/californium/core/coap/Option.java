/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add block1/block2 options 
 *                                                    to be decoded by toValueString 
 *                                                    (for message tracing)
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import org.eclipse.californium.core.coap.option.OptionDefinition;
import org.eclipse.californium.core.coap.option.OptionNumber;
import org.eclipse.californium.elements.util.DatagramWriter;

/**
 * Both requests and responses may include a list of one or more options.
 * 
 * An option number is constructed with a bit mask to indicate if an option is
 * Critical/Elective, Unsafe/Safe and in the case of Safe, also a Cache-Key
 * indication. See
 * <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.4.6" target=
 * "_blank">RFC7252 5.4.6. Option Numbers</a>.
 * 
 * <hr>
 * <blockquote>
 * 
 * <pre>
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * |           | NoCacheKey| U | C |
 * +---+---+---+---+---+---+---+---+
 * </pre>
 * 
 * </blockquote>
 * <hr>
 * 
 * For a given option number {@code onum} we can compute
 * 
 * <hr>
 * <blockquote>
 * 
 * <pre>
 * Critical = (onum &amp; 1);
 * UnSafe = (onum &amp; 2);
 * NoCacheKey = ((onum &amp; 0x1e) == 0x1c);
 * </pre>
 * 
 * </blockquote>
 * <hr>
 *
 * {@code CoAP} defines several option numbers detailed in
 * {@link OptionNumberRegistry}.
 * <p>
 * Class variables {@code number} and {@code value} directly maps to
 * {@code CoAP} request and response options as is. In {@code CoAP}
 * specification {@code number} is an option header key as {@code int} and
 * {@code value} is represented as a raw byte array {@code byte[]}. User must be
 * careful when using {@code value} directly as depending on actual option,
 * {@code value} may be {@code empty}, {@code opaque}, {@code uint} or
 * {@code string}. For example, for {@code uint} the number 0 is represented
 * with an empty option value (a zero-length sequence of bytes) and the number 1
 * by a single byte with the numerical value of 1 (bit combination 00000001 in
 * most significant bit first notation). A recipient MUST be prepared to process
 * values with leading zero bytes.
 * <p>
 * {@code Option} has a helper method, the {@link #toValueString()} taking into
 * account actual option type and how it may be represented in a native
 * {@code value}.
 * 
 * Since 3.8 {@link OptionDefinition} is introduced and is the preferred and
 * future way to specify, which option is represented. The option number on it's
 * own represents this only for the traditional options, but options introduced
 * with <a href="https://www.rfc-editor.org/rfc/rfc8323#section-5.2" target=
 * "_blank"> RFC8323 5.2. Signaling Option Numbers</a> dependent also on the
 * message code.
 * 
 * <pre>
 * <code>
 *   Option maxAge = StandardOptionRegistry.MAX_AGE.create(10);
 * </code>
 * </pre>
 *
 * @see OptionSet
 */
public abstract class Option implements OptionNumber, Comparable<OptionNumber> {

	/**
	 * The option definition.
	 * 
	 * @since 3.8
	 */
	private final OptionDefinition definition;

	// Constructors
	/**
	 * Instantiates a new option with the specified option definition.
	 * 
	 * @param definition the option definition
	 * @throws NullPointerException if the provided option definition is
	 *             {@code null}
	 * @since 4.0
	 */
	protected Option(OptionDefinition definition) {
		if (definition == null) {
			throw new NullPointerException("Definition must not be null!");
		}
		this.definition = definition;
	}

	// Getter and Setter

	/**
	 * Gets the option definition.
	 * 
	 * @return the option definition
	 * @since 3.8
	 */
	public OptionDefinition getDefinition() {
		return definition;
	}

	/**
	 * Gets the length of the option value.
	 *
	 * @return the length
	 */
	public abstract int getLength();

	/**
	 * Gets the option number.
	 *
	 * @return the option number
	 */
	@Override
	public int getNumber() {
		return definition.getNumber();
	}

	/**
	 * Writes the option value.
	 * 
	 * @param writer writer to write the value to
	 * @since 4.0
	 */
	public abstract void writeTo(DatagramWriter writer);

	/**
	 * Encodes option value.
	 * 
	 * @return encoded option value
	 * @since 4.0 (similar to previous getValue(), but reflects, that it is
	 *        rather a conversion than just a get.)
	 */
	public byte[] encode() {
		DatagramWriter writer = new DatagramWriter(getLength());
		writeTo(writer);
		return writer.toByteArray();
	}

	/**
	 * Checks if is this option is critical.
	 *
	 * @return true, if is critical
	 */
	public boolean isCritical() {
		// Critical = (onum & 1);
		return (getNumber() & 1) != 0;
	}

	/**
	 * Checks if is this option is unsafe.
	 *
	 * @return true, if is unsafe
	 */
	public boolean isUnSafe() {
		// UnSafe = (onum & 2);
		return (getNumber() & 2) != 0;
	}

	/**
	 * Checks if this option is a NoCacheKey.
	 *
	 * @return true, if is NoCacheKey
	 */
	public boolean isNoCacheKey() {
		// NoCacheKey = ((onum & 0x1e) == 0x1c);
		return (getNumber() & 0x1E) == 0x1C;
	}

	/**
	 * Checks if this options is a single value.
	 * 
	 * @return {@code true} for single value, {@code false} for repeatable
	 *         value.
	 * @since 4.0
	 */
	public boolean isSingleValue() {
		return getDefinition().isSingleValue();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(OptionNumber o) {
		return getNumber() - o.getNumber();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object o) {
		if (o == this) {
			return true;
		} else if (!(o instanceof Option)) {
			return false;
		}
		Option op = (Option) o;
		return definition.equals(op.definition);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return definition.hashCode();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(definition.getName());
		sb.append(": ");
		sb.append(toValueString());
		return sb.toString();
	}

	/**
	 * Renders the option value as string.
	 *
	 * @return the option value as string
	 */
	public abstract String toValueString();
}
