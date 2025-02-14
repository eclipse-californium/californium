/********************************************************************************
 * Copyright (c) 2025 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.scandium;

import java.net.InetSocketAddress;
import java.security.Principal;

import javax.crypto.SecretKey;

import org.eclipse.californium.scandium.dtls.Random;

/**
 * TLSKEYLOG.
 * <p>
 * The resource contains sensitive keys for encryption! Use it with reasonable
 * care!
 * 
 * @see <a href="https://tlswg.org/sslkeylogfile/draft-ietf-tls-keylogfile.html"
 *      target="_blank"> draft-ietf-tls-keylogfile</a>
 * @since 4.0
 */
public interface TlsKeyLog {

	/**
	 * Append new session key.
	 * 
	 * @param source client source address. Intended to be used to filter.
	 * @param principal client' principal. Intended to be used to filter.
	 * @param clientRandom client random of session
	 * @param masterSecret master secret of session
	 */
	void append(InetSocketAddress source, Principal principal, Random clientRandom, SecretKey masterSecret);

	/**
	 * Closes resources.
	 */
	void close();
}
