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

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * Both requests and responses may include a list of one or more options. An
 * Option number is constructed with a bit mask to indicate if an option is
 * Critical/Elective, Unsafe/Safe and in the case of Safe, also a Cache-Key
 * indication.
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
 * {@code CoAP} defines several option numbers detailed in {@link OptionNumberRegistry}.
 * <p>
 * Class variables {@code number} and {@code value} directly maps to {@code CoAP} request
 * and response options as is. In {@code CoAP} specification {@code number} is
 * an option header key as {@code int} and {@code value} is represented as
 * a raw byte array {@code byte[]}. User must be careful when using {@code value} directly
 * as depending on actual option, {@code value} may be {@code empty}, {@code opaque},
 * {@code uint} or {@code string}. For example, for {@code uint} the number 0 is represented
 * with an empty option value (a zero-length sequence of bytes) and the number 1 by a single
 * byte with the numerical value of 1 (bit combination 00000001 in most significant bit first
 * notation). A recipient MUST be prepared to process values with leading zero bytes.
 * <p>
 * {@code Option} has helper methods, namely {@link #getIntegerValue()} and
 * {@link #toValueString()} taking into account actual option type and how it
 * may be represented in a native {@code value}.
 *
 * @see OptionSet
 */
public class Option implements Comparable<Option> {

	/** The option number. */
	private final int number;

	/** The value as byte array. */
	private byte[] value; // not null

	/**
	 * Instantiates a new empty option.
	 */
	public Option() {
		this.number = OptionNumberRegistry.RESERVED_0;
		setValue(Bytes.EMPTY);
	}

	// Constructors

	/**
	 * Instantiates a new option with the specified option number.
	 * 
	 * The value must be set using one of the setters.
	 * 
	 * @param number the option number
	 * @see #setValue(byte[])
	 * @see #setStringValue(String)
	 * @see #setIntegerValue(int)
	 * @see #setLongValue(long)
	 */
	public Option(int number) {
		this.number = number;
	}

	/**
	 * Instantiates a new option with the specified option number and encodes
	 * the specified string as option value.
	 * 
	 * @param number the number
	 * @param str the option value as string
	 * @throws NullPointerException if value is {@code null}
	 * @throws IllegalArgumentException if value length doesn't match the option
	 *             definition.
	 * @since 3.0 validate the value and throws exception on mismatch
	 */
	public Option(int number, String str) {
		this.number = number;
		setStringValue(str);
	}

	/**
	 * Instantiates a new option with the specified option number and encodes
	 * the specified integer as option value.
	 *
	 * @param number the option number
	 * @param val the option value as integer
	 * @throws IllegalArgumentException if value length doesn't match the option
	 *             definition.
	 * @since 3.0 validate the value and throws exception on mismatch
	 */
	public Option(int number, int val) {
		this.number = number;
		setIntegerValue(val);
	}

	/**
	 * Instantiates a new option with the specified option number and encodes
	 * the specified long as option value.
	 *
	 * @param number the option number
	 * @param val the option value as long
	 * @throws IllegalArgumentException if value length doesn't match the option
	 *             definition.
	 * @since 3.0 validate the value and throws exception on mismatch
	 */
	public Option(int number, long val) {
		this.number = number;
		setLongValue(val);
	}

	/**
	 * Instantiates a new option with an arbitrary byte array as value.
	 *
	 * @param number the option number
	 * @param opaque the option value in bytes
	 * @throws NullPointerException if value is {@code null}
	 * @throws IllegalArgumentException if value length doesn't match the option
	 *             definition.
	 * @since 3.0 validate the value and throws exception on mismatch
	 */
	public Option(int number, byte[] opaque) {
		this.number = number;
		setValue(opaque);
	}

	// Getter and Setter

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
		return number;
	}

	/**
	 * Gets the option value.
	 *
	 * @return the option value
	 * @throws IllegalStateException if value was not set before (since 3.0).
	 */
	public byte[] getValue() {
		if (value == null) {
			String name = OptionNumberRegistry.toString(number);
			throw new IllegalStateException(name + " option value must be set before!");
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
		return new String(getValue(), CoAP.UTF8_CHARSET);
	}

	/**
	 * Gets the option value as integer. Handles cases where {@code value}
	 * contains leading 0's or a case where {@code value} is empty which
	 * returns 0.
	 *
	 * @return the integer value
	 * @throws IllegalStateException if value was not set before (since 3.0).
	 */
	public int getIntegerValue() {
		int ret = 0;
		byte[] value = getValue();
		for (int i = 0; i < value.length; i++) {
			ret += (value[value.length - i - 1] & 0xFF) << (i * 8);
		}
		return ret;
	}

	/**
	 * Gets the option value as long. Handles cases where {@code value}
	 * contains leading 0's or a case where {@code value} is empty which
	 * returns 0.
	 *
	 * @return the long value
	 * @throws IllegalStateException if value was not set before (since 3.0).
	 */
	public long getLongValue() {
		long ret = 0;
		byte[] value = getValue();
		for (int i = 0; i < value.length; i++) {
			ret += (long) (value[value.length - i - 1] & 0xFF) << (i * 8);
		}
		return ret;
	}

	/**
	 * Sets the option value.
	 *
	 * @param value the new value
	 * @throws NullPointerException if value is {@code null}
	 * @throws IllegalArgumentException if value length doesn't match the option
	 *             definition.
	 * @since 3.0 validate the value and throws exception on mismatch
	 */
	public void setValue(byte[] value) {
		if (value == null) {
			String name = OptionNumberRegistry.toString(number);
			throw new NullPointerException(name + " option value must not be null!");
		}
		OptionNumberRegistry.assertValueLength(number, value.length);
		this.value = value;
	}

	/**
	 * Sets the option value from a string.
	 *
	 * @param str the new option value as string
	 * @throws NullPointerException if value is {@code null}
	 * @throws IllegalArgumentException if value length doesn't match the option
	 *             definition.
	 * @since 3.0 validate the value and throws exception on mismatch
	 */
	public void setStringValue(String str) {
		setValue(str == null ? null : str.getBytes(CoAP.UTF8_CHARSET));
	}

	/**
	 * Sets the option value from an integer.
	 *
	 * @param val the new option value as integer
	 * @throws IllegalArgumentException if value length doesn't match the option
	 *             definition.
	 * @since 3.0 validate the value and throws exception on mismatch
	 */
	public void setIntegerValue(int val) {
		int length = (Integer.SIZE - Integer.numberOfLeadingZeros(val) + 7) / Byte.SIZE;
		byte[] value = new byte[length];
		for (int i = 0; i < length; i++) {
			value[length - i - 1] = (byte) (val >> i * 8);
		}
		setValue(value);
	}

	/**
	 * Sets the option value from a long.
	 *
	 * @param val the new option value as long
	 * @throws IllegalArgumentException if value length doesn't match the option
	 *             definition.
	 * @since 3.0 validate the value and throws exception on mismatch
	 */
	public void setLongValue(long val) {
		int length = (Long.SIZE - Long.numberOfLeadingZeros(val) + 7) / Byte.SIZE;
		byte[] value = new byte[length];
		for (int i = 0; i < length; i++) {
			value[length - i - 1] = (byte) (val >> i * 8);
		}
		setValue(value);
	}

	/**
	 * Checks if is this option is critical.
	 *
	 * @return true, if is critical
	 */
	public boolean isCritical() {
		// Critical = (onum & 1);
		return (number & 1) != 0;
	}

	/**
	 * Checks if is this option is unsafe.
	 *
	 * @return true, if is unsafe
	 */
	public boolean isUnSafe() {
		// UnSafe = (onum & 2);
		return (number & 2) != 0;
	}

	/**
	 * Checks if this option is a NoCacheKey.
	 *
	 * @return true, if is NoCacheKey
	 */
	public boolean isNoCacheKey() {
		// NoCacheKey = ((onum & 0x1e) == 0x1c);
		return (number & 0x1E) == 0x1C;
	}

	/* (non-Javadoc)
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(Option o) {
		return number - o.number;
	}

	/* (non-Javadoc)
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
		return number == op.number && Arrays.equals(value, op.value);
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return number * 31 + Arrays.hashCode(value);
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(OptionNumberRegistry.toString(number));
		sb.append(": ");
		sb.append(toValueString());
		return sb.toString();
	}

	/**
	 * Renders the option value as string. Takes into account of option type,
	 * thus giving more accurate representation of an option {@code value}.
	 * Formats {@code value} as integer or string if so defined in
	 * {@link OptionNumberRegistry}. In case of option {@code value} is just
	 * an opaque byte array, formats this value as hex string.
	 *
	 * @return the option value as string
	 */
	public String toValueString() {
		if (value == null) {
			return "not available";
		}
		switch (OptionNumberRegistry.getFormatByNr(number)) {
		case INTEGER:
			if (number==OptionNumberRegistry.ACCEPT || number==OptionNumberRegistry.CONTENT_FORMAT) return "\""+MediaTypeRegistry.toString(getIntegerValue())+"\"";
			else if (number==OptionNumberRegistry.BLOCK1 || number==OptionNumberRegistry.BLOCK2) return "\""+ new BlockOption(value) +"\"";
			else return Integer.toString(getIntegerValue());
		case STRING:
			return "\""+this.getStringValue()+"\"";
		case EMPTY:
			return "";
		default:
			return "0x" + StringUtil.byteArray2Hex(this.getValue());
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
