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
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.ConnectionStore;
import org.eclipse.californium.scandium.dtls.ResumptionVerificationResult;
import org.eclipse.californium.scandium.dtls.SessionId;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * Resumption verifier using the provided
 * {@link ConnectionStore}.
 * 
 * If not {@link ConnectionStore} is provided with
 * {@link #setConnectionStore(ConnectionStore)}, the
 * {@link DTLSConnector} will set its connection store as default on
 * initialization.
 * 
 * @since 3.0
 */
public class ConnectionStoreResumptionVerifier implements ResumptionVerifier {

	/**
	 * Connection store to lookup the dtls session.
	 */
	private volatile ConnectionStore connectionStore;

	/**
	 * Create a resumption verifier based on the
	 * {@link ConnectionStore} of the {@link DTLSConnector}.
	 */
	public ConnectionStoreResumptionVerifier() {
	}

	/**
	 * Create a resumption verifier based on the provided
	 * {@link ConnectionStore}.
	 * 
	 * @param connectionStore connection store to lookup the dtls session.
	 */
	public ConnectionStoreResumptionVerifier(ConnectionStore connectionStore) {
		setConnectionStore(connectionStore);
	}

	/**
	 * Checks, if the verifier has already a connection store.
	 * 
	 * @return {@code true}, if the connection store is already available,
	 *         {@code false}, otherwise.
	 */
	public boolean hasConnectionStore() {
		return connectionStore != null;
	}

	/**
	 * Sets the connection store.
	 * 
	 * @param connectionStore connection store
	 * @throws NullPointerException if the connection store is {@code null}.
	 */
	public void setConnectionStore(ConnectionStore connectionStore) {
		if (connectionStore == null) {
			throw new NullPointerException("Connection store must not be null!");
		}
		this.connectionStore = connectionStore;
	}

	@Override
	public ResumptionVerificationResult verifyResumptionRequest(final ConnectionId cid, final ServerNames serverName,
			final SessionId sessionId) {
		DTLSSession session = connectionStore.find(sessionId);
		return new ResumptionVerificationResult(cid, session, null);
	}

	@Override
	public void setResultHandler(HandshakeResultHandler resultHandler) {
		// empty implementation
	}
}
