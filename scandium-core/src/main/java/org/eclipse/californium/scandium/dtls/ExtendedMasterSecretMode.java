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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

/**
 * Extended master secret mode.
 * <p>
 * See <a href="https://tools.ietf.org/html/rfc7627">RFC 7627</a> for additional
 * details.
 * </p>
 * <p>
 * <a href="https://tools.ietf.org/html/rfc7925#section-16">RFC7925, 16. Session
 * Hash</a> recommends to use this extension. Please, obey the different
 * behavior on session resumption according
 * <a href="https://tools.ietf.org/html/rfc7627#section-5.3">RFC 7627, 5.3.
 * Client and Server Behavior: Abbreviated Handshake</a>, if one side doesn't
 * support this extension.
 * </p>
 * 
 * @since 3.0
 */
public enum ExtendedMasterSecretMode {

	/**
	 * Disable the use of the extended master secret.
	 */
	NONE,
	/**
	 * Optionally use the extended master secret. Session without extended
	 * master secret may be resumed. Not RFC 7627 compliant.
	 */
	OPTIONAL,
	/**
	 * Enable the use of the extended master secret. Session without extended
	 * master secret can not be resumed. The server will not assign a session
	 * ID, if the client doesn't use the extended master secret. That prevents
	 * such a client from accidentally resume the session. RFC 7627 compliant.
	 */
	ENABLED,
	/**
	 * Requires the use of the extended master secret.
	 */
	REQUIRED;

	/**
	 * Checks, if provided mode is contained in this mode.
	 * 
	 * @param mode mode to be compared
	 * @return {@code true}, if the {@link #ordinal()} of this mode is larger or
	 *         equal to the one of the provided mode. {@code false}, otherwise.
	 */
	public boolean is(ExtendedMasterSecretMode mode) {
		return ordinal() >= mode.ordinal();
	}
}
