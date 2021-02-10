/*******************************************************************************
 * Copyright (c) 2016, 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.util;

import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.HelloExtensions;
import org.eclipse.californium.scandium.util.ServerName.NameType;

/**
 * A container for server names and their name type.
 *
 */
public final class ServerNames implements Iterable<ServerName> {
	private static final int LIST_LENGTH_BITS = 16;

	private final Set<ServerName> names;
	int encodedLength; // overall length

	private ServerNames() {
		names = new LinkedHashSet<>();
	}

	private ServerNames(final ServerName serverName) {
		this();
		add(serverName);
	}

	/**
	 * Creates an empty server name list.
	 * 
	 * @return The new instance.
	 */
	public static ServerNames newInstance() {
		return new ServerNames();
	}

	/**
	 * Creates a new server name list from an initial server name.
	 * 
	 * @param serverName The server name to add.
	 * @return The new instance.
	 */
	public static ServerNames newInstance(final ServerName serverName) {
		if (serverName == null) {
			throw new NullPointerException("server name must not be null");
		} else {
			return new ServerNames(serverName);
		}
	}

	/**
	 * Creates a new server name list from an initial host name.
	 * 
	 * @param hostName The host name to add as {@link NameType#HOST_NAME}.
	 * @return The new instance.
	 */
	public static ServerNames newInstance(final String hostName) {
		if (hostName == null) {
			throw new NullPointerException("host name must not be null");
		} else {
			return new ServerNames(ServerName.from(NameType.HOST_NAME, hostName.getBytes(ServerName.CHARSET)));
		}
	}

	/**
	 * Adds a server name to this list.
	 * 
	 * @param serverName The server name to add.
	 * @return This instance for command chaining.
	 */
	public ServerNames add(final ServerName serverName) {

		if (serverName == null) {
			throw new NullPointerException("server name must not be null");
		} else if (names.contains(serverName)) {
			throw new IllegalStateException("there already is a name of the given type");
		} else {
			names.add(serverName);
			encodedLength += 1; // type code
			encodedLength += 2; // name length
			encodedLength += serverName.getName().length;
			return this;
		}
	}

	/**
	 * Gets the number of bytes this server name list is encoded to.
	 * 
	 * @return The length in bytes.
	 */
	public int getEncodedLength() {
		return encodedLength;
	}

	/**
	 * Gets the number of names contained in this list.
	 * 
	 * @return The number of entries.
	 */
	public int size() {
		return names.size();
	}

	/**
	 * Gets the name value of a server name of a particular type.
	 * 
	 * @param type The name type.
	 * @return The name or {@code null} if no name of the given type is part of the extension.
	 */
	public byte[] get(final ServerName.NameType type) {
		for (ServerName name : names) {
			if (name.getType().equals(type)) {
				return name.getName();
			}
		}
		return null;
	}

	public void encode(DatagramWriter writer) {
		writer.write(encodedLength, LIST_LENGTH_BITS); //server_names_list_length

		for (ServerName serverName : names) {
			writer.writeByte(serverName.getType().getCode()); // name type
			writer.writeVarBytes(serverName.getName(), HelloExtensions.LENGTH_BITS); // name length
		}
	}

	public void decode(DatagramReader reader) {
		int listLengthBytes = reader.read(LIST_LENGTH_BITS);
		DatagramReader rangeReader = reader.createRangeReader(listLengthBytes);
		while (rangeReader.bytesAvailable()) {
			NameType nameType = NameType.fromCode(rangeReader.readNextByte());
			switch (nameType) {
			case HOST_NAME:
				byte[] hostname = rangeReader.readVarBytes(HelloExtensions.LENGTH_BITS);
				add(ServerName.from(nameType, hostname));
				break;
			default:
				throw new IllegalArgumentException("ServerNames: unknown name_type!", new IllegalArgumentException(nameType.name()));
			}
		}
	}

	/**
	 * Gets the server name of a particular type.
	 * 
	 * @param type The name type.
	 * @return The server name or {@code null} if no server name of the given type is part of the extension.
	 */
	public ServerName getServerName(final ServerName.NameType type) {
		for (ServerName name : names) {
			if (name.getType().equals(type)) {
				return name;
			}
		}
		return null;
	}

	@Override
	public Iterator<ServerName> iterator() {
		return names.iterator();
	}

	@Override
	public String toString() {
		StringBuilder b = new StringBuilder("ServerNames[");
		Iterator<ServerName> iter = names.iterator();
		while (iter.hasNext()) {
			b.append(iter.next().getNameAsString());
			if (iter.hasNext()) {
				b.append(", ");
			}
		}
		b.append("]");
		return b.toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		for (ServerName name : names) {
			result = prime * result + name.hashCode();
		}
		return result;
	}

	@Override
	public boolean equals(Object object) {
		if (this == object)
			return true;
		if (object == null)
			return false;
		if (getClass() != object.getClass())
			return false;
		ServerNames other = (ServerNames) object;
		if (names.size() != other.names.size()) {
			return false;
		}
		return names.containsAll(other.names);
	}
}