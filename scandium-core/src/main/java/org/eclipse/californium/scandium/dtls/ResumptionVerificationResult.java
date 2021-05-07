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

import org.eclipse.californium.scandium.auth.ApplicationLevelInfoSupplier;
import org.eclipse.californium.scandium.dtls.resumption.ResumptionVerifier;

/**
 * Result of resumption verification.
 * 
 * @see ResumptionVerifier
 * @since 3.0
 */
public final class ResumptionVerificationResult extends HandshakeResult {

	private final DTLSSession session;

	/**
	 * Create result.
	 * 
	 * @param cid connection id
	 * @param session valid matching session. {@code null}, if no session is
	 *            available or session is not valid for resumption.
	 * @param customArgument custom argument. May be {@code null}. Passed to
	 *            {@link ApplicationLevelInfoSupplier} by the
	 *            {@link Handshaker}, if a {@link ApplicationLevelInfoSupplier}
	 *            is available.
	 * @throws NullPointerException if cid is {@code null}.
	 */
	public ResumptionVerificationResult(ConnectionId cid, DTLSSession session, Object customArgument) {
		super(cid, customArgument);
		this.session = session;
	}

	/**
	 * Get verified session.
	 * 
	 * @return verified session, or, {@code null}, if not available or not valid
	 *         for resumption.
	 */
	public DTLSSession getDTLSSession() {
		return session;
	}

}
