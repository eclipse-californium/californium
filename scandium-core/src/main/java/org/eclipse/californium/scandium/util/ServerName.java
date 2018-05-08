/*******************************************************************************
 * Copyright (c) 2016, 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.util;

import java.nio.charset.Charset;
import java.util.Arrays;

import org.eclipse.californium.elements.util.StandardCharsets;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * A typed server name as defined by RFC 6066, Section 3.
 *
 */
public class ServerName {

	/**
	 * The character set to use for encoding host names.
	 */
	public static final Charset CHARSET = StandardCharsets.US_ASCII;

	private final NameType type;
	private final byte[] name;

	private ServerName(final NameType type, final byte[] name) {
		this.type = type;
		this.name = name;
	}

	/**
	 * Creates a new instance for a type and name.
	 * <p>
	 * If the name is a host name then this method delegates
	 * to {@link #fromHostName(String)}.
	 * 
	 * @param type The type of name.
	 * @param name The name's byte encoding.
	 * @return The new instance.
	 * @throws NullPointerException if any of the parameters is {@code null}.
	 */
	public static ServerName from(final NameType type, final byte[] name) {
		if (type == null) {
			throw new NullPointerException("type must not be null");
		} else if (name == null) {
			throw new NullPointerException("name must not be null");
		} else if (type == NameType.HOST_NAME) {
			return fromHostName(new String(name, CHARSET));
		} else {
			return new ServerName(type, name);
		}
	}

	/**
	 * Creates a new instance for a host name.
	 * 
	 * @param hostName The host name. All non-ASCII characters will be replaced
	 *                 with the JRE's default replacement character. The name
	 *                 will be converted to lower case.
	 * @return The new instance.
	 * @throws NullPointerException if the host name is {@code null}.
	 * @throws IllegalArgumentException if the given name is not a valid host name
	 *               as per <a href="http://tools.ietf.org/html/rfc1123">RFC 1123</a>.
	 */
	public static ServerName fromHostName(final String hostName) {
		if (hostName == null) {
			throw new NullPointerException("host name must not be null");
		} else if (StringUtil.isValidHostName(hostName)) {
			return new ServerName(NameType.HOST_NAME, hostName.toLowerCase().getBytes(CHARSET));
		} else {
			throw new IllegalArgumentException("not a valid host name");
		}
	}

	/**
	 * Gets the name.
	 * 
	 * @return The name.
	 */
	public byte[] getName() {
		return name;
	}

	/**
	 * Gets the name as a string using ASCII encoding.
	 * 
	 * @return the name.
	 */
	public String getNameAsString() {
		return new String(name, CHARSET);
	}

	/**
	 * Gets this name's type.
	 * 
	 * @return The type.
	 */
	public NameType getType() {
		return type;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(name);
		result = prime * result + ((type == null) ? 0 : type.hashCode());
		return result;
	}

	/**
	 * Checks whether this instance is the same as another object.
	 * 
	 * @param obj The object to compare to.
	 * @return {@code true} if the other object is a {@code ServerName} and has the
	 *         same type and name property values.
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ServerName other = (ServerName) obj;
		if (!Arrays.equals(name, other.name)) {
			return false;
		}
		if (type != other.type) {
			return false;
		}
		return true;
	}


	/**
	 * The enumeration of name types defined for the <em>Server Name Indication</em> extension.
	 *
	 */
	public enum NameType {

		/**
		 * The host name type.
		 */
		HOST_NAME((byte) 0x00),
		/**
		 * Undefined type.
		 */
		UNDEFINED((byte) 0xFF);

		private byte code;

		private NameType(final byte code) {
			this.code = code;
		}

		/**
		 * Gets the type's code.
		 * 
		 * @return The code.
		 */
		public byte getCode() {
			return code;
		}

		/**
		 * Gets the name type for a code.
		 * 
		 * @param code The type code.
		 * @return The type or {@code null} if no type with the given code is defined.
		 */
		public static NameType fromCode(final byte code) {
			for (NameType type : values()) {
				if (type.code == code) {
					return type;
				}
			}
			return UNDEFINED;
		}
	}
}
