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
package org.eclipse.californium.scandium.util.backwardscompatibility;

import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.scandium.dtls.HelloExtensions;
import org.eclipse.californium.scandium.util.ServerName;
import org.eclipse.californium.scandium.util.ServerName.NameType;

/**
 * A container for server names and their name type.
 *
 */
public final class BackwardsCompatibleServerNames implements Iterable<ServerName> {

	private static final int LIST_LENGTH_BITS = 16;

	private final Set<ServerName> names = new LinkedHashSet<>();

	private void add(final ServerName serverName) {

		if (serverName == null) {
			throw new NullPointerException("server name must not be null");
		} else if (names.contains(serverName)) {
			throw new IllegalStateException("there already is a name of the given type");
		} else {
			names.add(serverName);
		}
	}

	public void decode(DatagramReader reader) {
		int listLengthBytes = reader.read(LIST_LENGTH_BITS);
		DatagramReader rangeReader = reader.createRangeReader(listLengthBytes);
		while (rangeReader.bytesAvailable()) {
			NameType nameType = NameType.fromCode(rangeReader.readNextByte());
			switch (nameType) {
			case HOST_NAME:
				byte[] hostname = readHostName(rangeReader);
				add(ServerName.from(nameType, hostname));
				break;
			default:
				throw new IllegalArgumentException("ServerNames: unknown name_type!",
						new IllegalArgumentException(nameType.name()));
			}
		}
	}

	private static byte[] readHostName(final DatagramReader reader) {

		if (reader.bitsLeft() >= HelloExtensions.LENGTH_BITS) {
			int length = reader.read(HelloExtensions.LENGTH_BITS);
			if (reader.bytesAvailable(length)) {
				return reader.readBytes(length);
			}
		}
		throw new IllegalArgumentException("ServerNames: no hostname found!");
	}

	@Override
	public Iterator<ServerName> iterator() {
		return names.iterator();
	}
}
