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
package org.eclipse.californium.scandium.dtls.resumption;

import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.ResumptionVerificationResult;
import org.eclipse.californium.scandium.dtls.ResumptionSupportingConnectionStore;
import org.eclipse.californium.scandium.dtls.SessionId;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * Resumption verifier.
 * 
 * If a client provided a session id in the client hello, this verifier is used
 * to verify, if there is a valid session to resume. An implementation may check
 * a maximum time, or, if the credentials are expired (e.g. x509 valid range).
 * The default verifier will just checks, if a DTLS session with that session id
 * is available in the {@link ResumptionSupportingConnectionStore}.
 * 
 * @since 3.0
 */
public interface ResumptionVerifier {

	/**
	 * Checks, if the session id is matching and the client hello may bypass the
	 * cookie validation without using a hello verify request.
	 * 
	 * Note: this function must return immediately.
	 * 
	 * @param sessionId session id
	 * @return {@code true}, if valid and no hello verify request is required,
	 *         {@code false}, otherwise.
	 */
	boolean skipRequestHelloVerify(SessionId sessionId);

	/**
	 * Verify resumption request.
	 * 
	 * Either return the result, or {@code null} and process the request
	 * asynchronously. The {@link ResumptionVerificationResult} must contain the
	 * CID, and the DTLS session, if available. If the result is not returned,
	 * it is passed asynchronously to the result handler, provided during
	 * {@link DTLSConnector} initialization by
	 * {@link #setResultHandler(HandshakeResultHandler)}.
	 * 
	 * @param cid connection id
	 * @param serverNames server names
	 * @param sessionId session id
	 * @return resumption result, or {@code null}, if result is provided
	 *         asynchronous.
	 */
	ResumptionVerificationResult verifyResumptionRequest(ConnectionId cid, ServerNames serverNames,
			SessionId sessionId);

	/**
	 * Set the handler for asynchronous master secret results.
	 * 
	 * Called during initialization of the {@link DTLSConnector}. Synchronous
	 * implementations may just ignore this using an empty implementation.
	 * 
	 * @param resultHandler handler for asynchronous master secret results. This
	 *            handler MUST NOT be called from the thread calling
	 *            {@link #verifyResumptionRequest(ConnectionId, ServerNames, SessionId)},
	 *            instead just return the result there.
	 */
	void setResultHandler(HandshakeResultHandler resultHandler);
}
