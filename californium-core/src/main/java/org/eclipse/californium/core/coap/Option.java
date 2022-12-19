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

import java.util.Arrays;

import org.eclipse.californium.core.coap.option.EmptyOptionDefinition;
import org.eclipse.californium.core.coap.option.IntegerOptionDefinition;
import org.eclipse.californium.core.coap.option.OpaqueOptionDefinition;
import org.eclipse.californium.core.coap.option.OptionDefinition;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.core.coap.option.StringOptionDefinition;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * Both requests and responses may include a list of one or more options.
 * 
 * An option number is constructed with a bit mask to indicate if an option is
 * Critical/Elective, Unsafe/Safe and in the case of Safe, also a Cache-Key
 * indication. See <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.4.6"
 * target= "_blank">RFC7252 5.4.6. Option Numbers</a>.
 * 
 * <hr><blockquote><pre>
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * |           | NoCacheKey| U | C |
 * +---+---+---+---+---+---+---+---+
 * </pre></blockquote><hr>
 * 
 * For a given option number {@code onum} we can compute
 * 
 * <hr><blockquote><pre>
 * Critical = (onum &amp; 1);
 * UnSafe = (onum &amp; 2);
 * NoCacheKey = ((onum &amp; 0x1e) == 0x1c);
 * </pre></blockquote><hr>
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
 * {@code Option} has helper methods, namely {@link #getIntegerValue()} and
 * {@link #toValueString()} taking into account actual option type and how it
 * may be represented in a native {@code value}.
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
public class Option implements Comparable<Option> {

	/**
	 * The option definition.
	 * 
	 * @since 3.8
	 */
	private final OptionDefinition definition;

	/** The value as byte array. */
	private byte[] value; // not null

	/**
	 * Instantiates a new empty option.
	 */
	public Option() {
		this.definition = new OpaqueOptionDefinition(OptionNumberRegistry.RESERVED_0, "Reserved 0");
		setValue(Bytes.EMPTY);
	}

	// Constructors

	/**
	 * Instantiates a new option with the specified option number.
	 * 
	 * Note: The value must be set using one of the setters or other
	 * constructors. Since 3.0, the value will be validated. Using
	 * {@code Bytes.EMPTY} as default would fail in too many cases.
	 * 
	 * @param number the option number
	 * @throws IllegalArgumentException if option number is not supported by
	 *             {@link StandardOptionRegistry#getDefaultOptionRegistry()}.
	 * @see #setValue(byte[])
	 * @see #setStringValue(String)
	 * @see #setIntegerValue(int)
	 * @see #setLongValue(long)
	 * @deprecated use an {@link #Option(OptionDefinition)}
	 */
	@Deprecated
	public Option(int number) {
		definition = StandardOptionRegistry.getDefaultOptionRegistry().getDefinitionByNumber(number);
		if (definition == null) {
			throw new IllegalArgumentException("Unkonwn " + number + " not supported!");
		}
	}

	/**
	 * Instantiates a new option with the specified option number.
	 * 
	 * Note: The value must be set using one of the setters or other
	 * constructors. Using {@code Bytes.EMPTY} as default fails in too many
	 * cases.
	 * 
	 * @param definition the option definition
	 * @see #setValue(byte[])
	 * @see #setStringValue(String)
	 * @see #setIntegerValue(int)
	 * @see #setLongValue(long)
	 * @since 3.8
	 */
	public Option(OptionDefinition definition) {
		if (definition == null) {
			throw new NullPointerException("Definition must not be null!");
		}
		this.definition = definition;
	}

	/**
	 * Instantiates a new empty option with the specified empty option
	 * definition.
	 * 
	 * @param definition the option definition
	 * @since 3.8
	 */
	public Option(EmptyOptionDefinition definition) {
		this.definition = definition;
		setValue(Bytes.EMPTY);
	}

	/**
	 * Instantiates a new option with the specified option definition and with
	 * an arbitrary byte array as value.
	 * 
	 * @param definition the option definition
	 * @param value the option value in bytes
	 * @throws NullPointerException if value is {@code null}
	 * @throws IllegalArgumentException if value doesn't match the option
	 *             definition.
	 * @since 3.8
	 */
	public Option(OptionDefinition definition, byte[] value) {
		this.definition = definition;
		setValue(value);
	}

	/**
	 * Instantiates a new option with the specified option definition and
	 * encodes the specified string as option value.
	 * 
	 * @param definition the option definition
	 * @param value the option value as string
	 * @throws NullPointerException if value is {@code null}
	 * @throws IllegalArgumentException if value doesn't match the option
	 *             definition.
	 * @since 3.8
	 */
	public Option(StringOptionDefinition definition, String value) {
		this.definition = definition;
		setStringValue(value);
	}

	/**
	 * Instantiates a new option with the specified option definition and
	 * encodes the specified integer as option value.
	 * 
	 * @param definition the option definition
	 * @param value the option value as integer
	 * @throws IllegalArgumentException if value doesn't match the option
	 *             definition.
	 * @since 3.8
	 */
	public Option(IntegerOptionDefinition definition, int value) {
		this.definition = definition;
		setIntegerValue(value);
	}

	/**
	 * Instantiates a new option with the specified option definition and
	 * encodes the specified long as option value.
	 * 
	 * @param definition the option definition
	 * @param value the option value as long
	 * @throws IllegalArgumentException if value doesn't match the option
	 *             definition.
	 * @since 3.8
	 */
	public Option(IntegerOptionDefinition definition, long value) {
		this.definition = definition;
		setLongValue(value);
	}

	/**
	 * Instantiates a new option with the specified option number and encodes
	 * the specified string as option value.
	 * 
	 * @param number the number
	 * @param value the option value as string
	 * @throws NullPointerException if value is {@code null}
	 * @throws IllegalArgumentException if option number is not supported by
	 *             {@link StandardOptionRegistry#getDefaultOptionRegistry()} or
	 *             the value doesn't match the option definition.
	 * @since 3.0 validate the value and throws exception on mismatch
	 * @deprecated use {@link #Option(StringOptionDefinition, String)}
	 */
	@Deprecated
	public Option(int number, String value) {
		this(number);
		setStringValue(value);
	}

	/**
	 * Instantiates a new option with the specified option number and encodes
	 * the specified integer as option value.
	 *
	 * @param number the option number
	 * @param val the option value as integer
	 * @throws IllegalArgumentException if option number is not supported by
	 *             {@link StandardOptionRegistry#getDefaultOptionRegistry()} or
	 *             the value doesn't match the option definition.
	 * @since 3.0 validate the value and throws exception on mismatch
	 * @deprecated use {@link #Option(IntegerOptionDefinition, int)}
	 */
	@Deprecated
	public Option(int number, int val) {
		this(number);
		setIntegerValue(val);
	}

	/**
	 * Instantiates a new option with the specified option number and encodes
	 * the specified long as option value.
	 *
	 * @param number the option number
	 * @param val the option value as long
	 * @throws IllegalArgumentException if option number is not supported by
	 *             {@link StandardOptionRegistry#getDefaultOptionRegistry()} or
	 *             the value doesn't match the option definition.
	 * @since 3.0 validate the value and throws exception on mismatch
	 * @deprecated use {@link #Option(IntegerOptionDefinition, long)}
	 */
	@Deprecated
	public Option(int number, long val) {
		this(number);
		setLongValue(val);
	}

	/**
	 * Instantiates a new option with an arbitrary byte array as value.
	 *
	 * @param number the option number
	 * @param opaque the option value in bytes
	 * @throws NullPointerException if value is {@code null}
	 * @throws IllegalArgumentException if option number is not supported by
	 *             {@link StandardOptionRegistry#getDefaultOptionRegistry()} or
	 *             the value doesn't match the option definition.
	 * @since 3.0 validate the value and throws exception on mismatch
	 * @deprecated use {@link #Option(OptionDefinition, byte[])}
	 */
	@Deprecated
	public Option(int number, byte[] opaque) {
		this(number);
		setValue(opaque);
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
	 * @throws IllegalStateException if value was not set before (since 3.0).
	 */
	public int getLength() {
		return getValue().length;
	}

	/**
	 * Gets the option number.
	 *
	 * @return the option number
	 */
	public int getNumber() {
		return definition.getNumber();
	}

	/**
	 * Gets the option value.
	 *
	 * @return the option value
	 * @throws IllegalStateException if value was not set before (since 3.0).
	 */
	public byte[] getValue() {
		if (value == null) {
			throw new IllegalStateException(definition.getName() + " option value must be set before!");
		}
		return value;
	}

	/**
	 * Gets the option value as string.
	 *
	 * @return the string value
	 * @throws IllegalStateException if value was not set before (since 3.0).
	 */
	public String getStringValue() {
		return StringOptionDefinition.getStringValue(getValue());
	}

	/**
	 * Gets the option value as integer.
	 * 
	 * Handles cases where {@code value} contains leading 0's or a case where
	 * {@code value} is empty which returns 0.
	 *
	 * @return the integer value
	 * @throws IllegalStateException if value was not set before (since 3.0).
	 */
	public int getIntegerValue() {
		return IntegerOptionDefinition.getIntegerValue(getValue());
	}

	/**
	 * Gets the option value as long.
	 * 
	 * Handles cases where {@code value} contains leading 0's or a case where
	 * {@code value} is empty which returns 0.
	 *
	 * @return the long value
	 * @throws IllegalStateException if value was not set before (since 3.0).
	 */
	public long getLongValue() {
		return IntegerOptionDefinition.getLongValue(getValue());
	}

	/**
	 * Sets the option value.
	 *
	 * @param value the new value
	 * @throws NullPointerException if value is {@code null}
	 * @throws IllegalArgumentException if value doesn't match the option
	 *             definition.
	 * @see OptionDefinition#assertValue(byte[])
	 * @since 3.0 validate the value and throws exception on mismatch
	 */
	public void setValue(byte[] value) {
		if (value == null) {
			throw new NullPointerException(definition.getName() + " option value must not be null!");
		}
		definition.assertValue(value);
		this.value = value;
	}

	/**
	 * Sets the option value from a string.
	 *
	 * @param str the new option value as string
	 * @throws NullPointerException if value is {@code null}
	 * @throws IllegalArgumentException if value doesn't match the option
	 *             definition.
	 * @since 3.0 validate the value and throws exception on mismatch
	 */
	public void setStringValue(String str) {
		setValue(StringOptionDefinition.setStringValue(str));
	}

	/**
	 * Sets the option value from an integer.
	 *
	 * @param val the new option value as integer
	 * @throws IllegalArgumentException if value doesn't match the option
	 *             definition.
	 * @since 3.0 validate the value and throws exception on mismatch
	 */
	public void setIntegerValue(int val) {
		setValue(IntegerOptionDefinition.setIntegerValue(val));
	}

	/**
	 * Sets the option value from a long.
	 *
	 * @param val the new option value as long
	 * @throws IllegalArgumentException if value doesn't match the option
	 *             definition.
	 * @since 3.0 validate the value and throws exception on mismatch
	 */
	public void setLongValue(long val) {
		setValue(IntegerOptionDefinition.setLongValue(val));
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

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(Option o) {
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
		return definition.equals(op.definition) && Arrays.equals(value, op.value);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return definition.hashCode() * 31 + Arrays.hashCode(value);
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
	 * Renders the option value as string. Takes into account of option type,
	 * thus giving more accurate representation of an option {@code value}.
	 * Formats {@code value} as integer or string if so defined in
	 * {@link OptionNumberRegistry}. In case of option {@code value} is just an
	 * opaque byte array, formats this value as hex string.
	 *
	 * @return the option value as string
	 */
	public String toValueString() {
		if (value == null) {
			return "not available";
		}
		switch (definition.getFormat()) {
		case INTEGER:
			if (StandardOptionRegistry.BLOCK1.equals(definition) || StandardOptionRegistry.BLOCK2.equals(definition))
				return "\"" + new BlockOption(value) + "\"";
			int iValue = getIntegerValue();
			if (StandardOptionRegistry.ACCEPT.equals(definition)
					|| StandardOptionRegistry.CONTENT_FORMAT.equals(definition))
				return "\"" + MediaTypeRegistry.toString(iValue) + "\"";
			if (StandardOptionRegistry.NO_RESPONSE.equals(definition))
				return "\"" + new NoResponseOption(iValue) + "\"";
			return Long.toString(getLongValue());
		case STRING:
			return "\"" + this.getStringValue() + "\"";
		case EMPTY:
			return "";
		default:
			return "0x" + StringUtil.byteArray2Hex(value);
		}
	}

	/**
	 * Sets the option value unchecked.
	 *
	 * For unit tests only!
	 * 
	 * @param value the new value
	 * @return this option
	 * @since 3.0
	 */
	Option setValueUnchecked(byte[] value) {
		this.value = value;
		return this;
	}

}
