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
 * CoAP defines several option numbers {@link OptionNumberRegistry}.
 */
public class Option implements Comparable<Option> {

	/** The option number. */
	private OptionNumberRegistry number;
	
	/** The value as byte array. */
	private byte[] value; // not null
	
	/**
	 * Instantiates a new empty option.
	 */
	public Option() {
		this.value = new byte[0];
	}
	
	// Constructors
	
	/**
	 * Instantiates a new option with the specified option number.
	 *
	 * @param number the option number
	 */
	public Option(OptionNumberRegistry number) {
		this.number = number;
		this.value = new byte[0];
	}
	
	/**
	 * Instantiates a new option with the specified option number and encodes
	 * the specified string as option value.
	 * 
	 * @param number the number
	 * @param str the option value as string
	 */
	public Option(OptionNumberRegistry number, String str) {
		this.number = number;
		setStringValue(str);
	}
	
	/**
	 * Instantiates a new option with the specified option number and encodes
	 * the specified integer as option value.
	 *
	 * @param number the option number
	 * @param val the option value as integer
	 */
	public Option(OptionNumberRegistry number, int val) {
		this.number = number;
		setIntegerValue(val);
	}
	
	/**
	 * Instantiates a new option with the specified option number and encodes
	 * the specified long as option value.
	 *
	 * @param number the option number
	 * @param val the option value as long
	 */
	public Option(OptionNumberRegistry number, long val) {
		this.number = number;
		setLongValue(val);
	}
	
	/**
	 * Instantiates a new option with an arbitrary byte array as value.
	 *
	 * @param number the option number
	 * @param opaque the option value in bytes
	 */
	public Option(OptionNumberRegistry number, byte[] opaque) {
		this.number = number;
		setValue(opaque);
	}
	
	// Getter and Setter
	
	/**
	 * Gets the length of the option value.
	 *
	 * @return the length
	 */
	public int getLength() {
		return value.length;
	}
	
	/**
	 * Gets the option number.
	 *
	 * @return the option number
	 */
	public OptionNumberRegistry getNumber() {
		return number;
	}

	/**
	 * Sets the option number.
	 *
	 * @param number the new option number
	 */
	public void setNumber(OptionNumberRegistry number) {
		this.number = number;
	}
	
	/**
	 * Gets the option value.
	 *
	 * @return the option value
	 */
	public byte[] getValue() {
		return value;
	}
	
	/**
	 * Gets the option value as string.
	 *
	 * @return the string value
	 */
	public String getStringValue() {
		return new String(value, CoAP.UTF8_CHARSET);
	}
	
	/**
	 * Gets the option value as integer.
	 *
	 * @return the integer value
	 */
	public int getIntegerValue() {
		int ret = 0;
		for (int i=0; i<value.length; i++) {
			ret <<= 8;
			ret |= (int) value[i] & 0xff;
		}
		return ret;
	}
	
	/**
	 * Gets the option value as long.
	 *
	 * @return the long value
	 */
	public long getLongValue() {
		long ret = 0;
		for (int i=0; i<value.length; i++) {
			ret <<= 8;
			ret |= (int) value[i] & 0xff;
		}
		return ret;
	}

	/**
	 * Sets the option value.
	 *
	 * @param value the new value
	 */
	public void setValue(byte[] value) {
		if (value == null)
			throw new NullPointerException();
		this.value = value;
	}
	
	/**
	 * Sets the option value from a string.
	 *
	 * @param str the new option value as string
	 */
	public void setStringValue(String str) {
		if (str == null)
			throw new NullPointerException();
		value = str.getBytes(CoAP.UTF8_CHARSET);
	}
	
	/**
	 * Sets the option value from an integer.
	 *
	 * @param val the new option value as integer
	 */
	public void setIntegerValue(int val) {
	    setLongValue((long)val & 0xffffffffL);
	}
	
	public void setLongValue(long val) {
	    long[] tab = {
	                         0x00L, // 0 bytes
	                         0x01L, // 1 byte
	                        0x100L, // 2 bytes
	                      0x10000L,
	                    0x1000000L,
	                  0x100000000L,
	                0x10000000000L,
	              0x1000000000000L, // 7 bytes
	    };
	    int length = 0, b = 4;
	    if (val < 0L || val >= 0x100000000000000L)
	        length = 8;
	    else {
	        // this loop repeats four times to get log_0x100(value) rounded upwards.
	        while (b != 0) {
	            if (val >= tab[length + b])
	                length += b;
	            b >>= 1;
	        }
	    }
	    value = new byte[length];
		while (length > 0) {
		    value[--length] = (byte) (val & 0xff);
		    val >>>= 8;
		}
	}

	/**
	 * Checks if is this option is critical.
	 *
	 * @return true, if is critical
	 */
	public boolean isCritical() {
		// Critical = (onum & 1);
	    return number.isCritical();
	}
	
	/**
	 * Checks if is this option is unsafe.
	 *
	 * @return true, if is unsafe
	 */
	public boolean isUnSafe() {
		// UnSafe = (onum & 2);
		return number.isUnsafe();
	}
	
	/**
	 * Checks if this option is a NoCacheKey.
	 *
	 * @return true, if is NoCacheKey
	 */
	public boolean isNoCacheKey() {
		// NoCacheKey = ((onum & 0x1e) == 0x1c);
		return number.isNoCacheKey();
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(Option o) {
		return number.getProtocolValue() - o.number.getProtocolValue();
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object o) {
		if (o == this)
			return true;
		if (!(o instanceof Option))
			return false;
		
		Option op = (Option) o;
		return number == op.number && Arrays.equals(value, op.value);
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return number.getProtocolValue()*31 + value.hashCode();
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(number.toString());
		sb.append(": ");
		sb.append(toValueString());
		return sb.toString();
	}
	
	/**
	 * Renders the option value as string.
	 * 
	 * @return the option value as string
	 */
	public String toValueString() {
		switch (number.getFormat()) {
		case INTEGER:
			if (number==OptionNumberRegistry.ACCEPT || number==OptionNumberRegistry.CONTENT_FORMAT) return "\""+MediaTypeRegistry.toString(getIntegerValue())+"\"";
			else if (number==OptionNumberRegistry.BLOCK1 || number==OptionNumberRegistry.BLOCK2) return "\""+ new BlockOption(value) +"\"";
			else return Integer.toString(getIntegerValue());
		case STRING:
			return "\""+this.getStringValue()+"\"";
		default:
			return toHexString(this.getValue());
		}
	}
	
	/*
	 * Converts the specified byte array to a hexadecimal string.
	 *
	 * @param bytes the byte array
	 * @return the hexadecimal code string
	 */
	private String toHexString(byte[] bytes) {
		   StringBuilder sb = new StringBuilder();
		   sb.append("0x");
		   for(byte b:bytes)
		      sb.append(String.format("%02x", b & 0xFF));
		   return sb.toString();
	}
}
