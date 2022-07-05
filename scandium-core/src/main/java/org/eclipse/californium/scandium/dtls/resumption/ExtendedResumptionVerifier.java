/*******************************************************************************
 * Copyright (c) 2022 Achim Kraus and others.
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
 *    Achim Kraus - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.resumption;

import org.eclipse.californium.scandium.dtls.ClientHello;
import org.eclipse.californium.scandium.dtls.ExtendedMasterSecretMode;

/**
 * Extended Resumption verifier.
 * 
 * An extended resumption verifier checks additionally, if no fallback to a full
 * handshake is required.
 * 
 * @since 3.6
 */
public interface ExtendedResumptionVerifier extends ResumptionVerifier {

	/**
	 * Checks, if the session id is matching and no fallback to a full handshake
	 * is required. If so, the client hello may bypass the cookie validation
	 * without using a hello verify request.
	 * 
	 * Note: this function must return immediately.
	 * 
	 * @param clientHello client hello message
	 * @param sniEnabled {@code true}, if SNI is enabled, {@code false},
	 *            otherwise.
	 * @param extendedMasterSecretMode the extended master secret mode.
	 * @return {@code true}, if valid and no hello verify request is required,
	 *         {@code false}, otherwise.
	 */
	boolean skipRequestHelloVerify(ClientHello clientHello, boolean sniEnabled,
			ExtendedMasterSecretMode extendedMasterSecretMode);
}
