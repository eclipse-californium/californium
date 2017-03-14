/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * A typed server name as defined by RFC 6066, Section 3.
 *
 */
public class ServerName {

	private final NameType type;
	private final byte[] name;

	private ServerName(final NameType type, final byte[] name) {
		this.type = type;
		this.name = name;
	}

	/**
	 * Creates a new instance for a type and name.
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
		} else {
			return new ServerName(type, name);
		}
	}

	/**
	 * Creates a new instance for a host name.
	 * 
	 * @param hostName The host name. All non-ASCII characters will be replaced with the JRE's default
	 *                 replacement character.
	 * @return The new instance.
	 * @throws NullPointerException if the host name is {@code null}.
	 */
	public static ServerName fromHostName(final String hostName) {
		if (hostName == null) {
			throw new NullPointerException("host name must not be null");
		} else {
			return new ServerName(NameType.HOST_NAME, hostName.getBytes(StandardCharsets.US_ASCII));
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
