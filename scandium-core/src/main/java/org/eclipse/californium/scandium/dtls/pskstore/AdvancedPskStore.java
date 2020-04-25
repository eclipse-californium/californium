/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *                    Inspired by the MasterSecretDeriver contribute
 *                    Jaimie Whiteside (Arm). 
 *                    Obsoletes that MasterSecretDeriver.
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.pskstore;

import java.net.InetSocketAddress;

import javax.crypto.SecretKey;

import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.PskSecretResultHandler;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * New advanded PSK store with support for asynchrounous PSK store and HSM.
 * 
 * Returns psk secret result instead of PSK's secret key. The secret must either
 * be a master secret (algorithm "MAC"), or a PSK secret key (algorithm "PSK").
 * If required, the psk secret result maybe returned asynchrounos using a
 * {@link PskSecretResultHandler}.
 * 
 * <p>
 * Synchronous example returning the PSK secret key:
 * 
 * <pre>
 * &#64;Override
 * public PskSecretResult generateMasterSecret(ConnectionId cid, ServerNames serverNames, PskPublicInformation identity,
 * 			String hmacAlgorithm, SecretKey otherSecret, byte[] seed) {
 * 		SecretKey pskSecret = ... func ... identity ...; // identity maybe normalized!
 * 		return new PskSecretResult(cid, identity, pskSecret);
 * }
 * </pre>
 *
 * Asynchronous example returning the master secret:
 * 
 * <pre>
 * &#64;Override
 * public PskSecretResult generateMasterSecret(ConnectionId cid, ServerNames serverNames, PskPublicInformation identity,
 * 			String hmacAlgorithm, SecretKey otherSecret, byte[] seed) {
 * 	
 * 		start ... func ... cid, servernames, identity, otherSecret, seed 
 * 			// calls processResult with generate master secret asynchronous;
 * 		return null; // returns null for asynchronous processing
 * }
 * 
 * &#64;Override
 * public void setResultHandler(PskSecretResultHandler resultHandler) {
 * 		this.resultHandler = resultHandler;
 * }
 * 
 * private void processResult(PskPublicInformation identity, ConnectionId cid,
 * 			SecretKey masterSecret) {
 * 		PskSecretResult result = new PskSecretResult(cid, identity, masterSecret);
 * 		resultHandler.apply(result);
 * }
 * </pre>
 * </p>
 */
public interface AdvancedPskStore {

	/**
	 * Check, if HSM supported ECDHE PSK cipher suites.
	 * 
	 * @return {@code true}, if ECDHE PSK cipher suites are supported,
	 *         {@code false}, if not.
	 */
	boolean hasEcdhePskSupported();

	/**
	 * Generate master secret.
	 * 
	 * Either return result, or {@code null} and return an asynchronous create
	 * {@link PskSecretResult} with the CID and master secret calling the result
	 * handler, provided during {@link DTLSConnector} initialization by
	 * {@link #setResultHandler(PskSecretResultHandler)}.
	 * 
	 * @param cid connection id for stateless asynchronous implementations.
	 * @param serverName server names. Maybe {@code null}, if SNI is not enabled
	 *            or not used by the client.
	 * @param identity psk identity. Maybe normalized
	 * @param hmacAlgorithm HMAC algorithm name for PRF.
	 * @param otherSecret other secert from ECDHE, or {@code null}. Must be
	 *            cloned for asynchrounous use.
	 * @param seed seed for PRF.
	 * @return master secret result, or {@code null}, if result is provided
	 *         asynchronous.
	 */
	PskSecretResult generateMasterSecret(ConnectionId cid, ServerNames serverName, PskPublicInformation identity,
			String hmacAlgorithm, SecretKey otherSecret, byte[] seed);

	/**
	 * Gets the <em>identity</em> to use for a PSK based handshake with a given
	 * peer.
	 * <p>
	 * A DTLS client uses this method to determine the identity to include in
	 * its <em>CLIENT_KEY_EXCHANGE</em> message during a PSK based DTLS
	 * handshake with the peer.
	 * 
	 * @param peerAddress The IP address and port of the peer to perform the
	 *            handshake with.
	 * @param virtualHost The virtual host at the peer to connect to. If
	 *            {@code null}, the identity will be looked up in the
	 *            <em>global</em> scope.
	 * @return The identity to use or {@code null} if no peer with the given
	 *         address and virtual host is registered.
	 * @throws NullPointerException if address is {@code null}.
	 */
	PskPublicInformation getIdentity(InetSocketAddress peerAddress, ServerNames virtualHost);

	/**
	 * Set the handler for asynchrouns master secret results.
	 * 
	 * Called during initialization of the {@link DTLSConnector}.
	 * 
	 * @param resultHandler handler for asynchrouns master secret results
	 */
	void setResultHandler(PskSecretResultHandler resultHandler);
}
