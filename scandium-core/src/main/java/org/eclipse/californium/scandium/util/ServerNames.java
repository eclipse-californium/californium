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

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * A container for server names and their name type.
 *
 */
public final class ServerNames implements Iterable<ServerName> {

	private final Set<ServerName> names;
	int encodedLength; // overall length

	private ServerNames() {
		names = new HashSet<>();
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
			throw new NullPointerException("name must not be null");
		} else {
			return new ServerNames(serverName);
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
	 * Gets the server name of a particular type.
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

	@Override
	public Iterator<ServerName> iterator() {
		return names.iterator();
	}
}