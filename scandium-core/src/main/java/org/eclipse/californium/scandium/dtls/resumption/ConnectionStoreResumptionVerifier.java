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
import org.eclipse.californium.scandium.dtls.ClientHello;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.ExtendedMasterSecretMode;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.ResumingServerHandshaker;
import org.eclipse.californium.scandium.dtls.ResumptionSupportingConnectionStore;
import org.eclipse.californium.scandium.dtls.ResumptionVerificationResult;
import org.eclipse.californium.scandium.dtls.SessionId;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * Resumption verifier using the provided
 * {@link ResumptionSupportingConnectionStore}.
 * 
 * If not {@link ResumptionSupportingConnectionStore} is provided with
 * {@link #setConnectionStore(ResumptionSupportingConnectionStore)}, the
 * {@link DTLSConnector} will set its connection store as default on
 * initialization.
 * 
 * @since 3.0
 */
public class ConnectionStoreResumptionVerifier implements ExtendedResumptionVerifier {

	/**
	 * Connection store to lookup the dtls session.
	 */
	private volatile ResumptionSupportingConnectionStore connectionStore;

	/**
	 * Create a resumption verifier based on the
	 * {@link ResumptionSupportingConnectionStore} of the {@link DTLSConnector}.
	 */
	public ConnectionStoreResumptionVerifier() {
	}

	/**
	 * Create a resumption verifier based on the provided
	 * {@link ResumptionSupportingConnectionStore}.
	 * 
	 * @param connectionStore connection store to lookup the dtls session.
	 */
	public ConnectionStoreResumptionVerifier(ResumptionSupportingConnectionStore connectionStore) {
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
	public void setConnectionStore(ResumptionSupportingConnectionStore connectionStore) {
		if (connectionStore == null) {
			throw new NullPointerException("Connection store must not be null!");
		}
		this.connectionStore = connectionStore;
	}

	@Override
	public boolean skipRequestHelloVerify(SessionId sessionId) {
		boolean result = false;
		ResumptionSupportingConnectionStore store = connectionStore;
		if (store != null) {
			DTLSSession session = store.find(sessionId);
			result = session != null;
			SecretUtil.destroy(session);
		}
		return result;
	}

	@Override
	public boolean skipRequestHelloVerify(ClientHello clientHello, boolean sniEnabled,
			ExtendedMasterSecretMode extendedMasterSecretMode) {
		boolean result = false;
		ResumptionSupportingConnectionStore store = connectionStore;
		if (store != null) {
			DTLSSession session = store.find(clientHello.getSessionId());
			if (session != null) {
				result = ResumingServerHandshaker.validateResumption(session, clientHello, sniEnabled,
						extendedMasterSecretMode);
				SecretUtil.destroy(session);
			}
		}
		return result;
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
