/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation.
 *                                                    Modified variant of ManInTheMiddle
 ******************************************************************************/

package org.eclipse.californium.secure.test;

import java.net.InetSocketAddress;
import java.util.Arrays;

import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.util.ServerNames;

public class FixPskStore implements PskStore {

	final String identity;
	final byte[] key;
	
	public FixPskStore(String identity, byte[] key) {
		this.identity = identity;
		this.key = Arrays.copyOf(key, key.length);
	}
	
	@Override
	public byte[] getKey(String identity) {
		return key;
	}

	@Override
	public byte[] getKey(ServerNames serverNames, String identity) {
		return key;
	}

	@Override
	public String getIdentity(InetSocketAddress inetAddress) {
		return identity;
	}

}
