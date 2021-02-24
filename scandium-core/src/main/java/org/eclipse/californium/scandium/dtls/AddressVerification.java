/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

/**
 * Address verification level.
 * 
 * @since 3.0 (replaces AvailableConnections)
 */
public class AddressVerification {

	/**
	 * Address verified by matching cookie.
	 */
	private final boolean matchingCookie;
	/**
	 * Address verified by matching session id.
	 */
	private final DTLSSession matchingSession;

	/**
	 * Creates a new address verification level.
	 * 
	 * @param matchingCookie {@code true}, if matching cookie is received,
	 *            {@code false}, otherwise.
	 * @param matchingSession the dtls session, if a matching session id is
	 *            received, {@code null}, otherwise.
	 * @throws IllegalArgumentException if neither the cookie nor the session id
	 *             was matching.
	 */
	public AddressVerification(boolean matchingCookie, DTLSSession matchingSession) {
		if (!matchingCookie && matchingSession == null) {
			throw new IllegalArgumentException("Either cookie or session must match!");
		}
		this.matchingCookie = matchingCookie;
		this.matchingSession = matchingSession;
	}

	/**
	 * Check, if the cookie has matched.
	 * 
	 * @return {@code true}, if cookie has matched, {@code false}, if not.
	 */
	public boolean hasMatchingCookie() {
		return matchingCookie;
	}

	/**
	 * Get matching session.
	 * 
	 * @return session, or {@code null}, if no matching session was found.
	 */
	public DTLSSession getMatchingSession() {
		return matchingSession;
	}
}
