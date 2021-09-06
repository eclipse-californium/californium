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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.x509;

import java.net.InetSocketAddress;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.CertificateVerificationResult;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * New advanced certificate verifier.
 * 
 * Returns certificate verification result. If required, the certificate
 * verification result maybe returned asynchronously using a
 * {@link HandshakeResultHandler}.
 * 
 * <p>
 * Synchronous example:
 * </p>
 * 
 * <pre>
 * &#64;Override
 * public CertificateVerificationResult verifyCertificate(ConnectionId cid, ServerNames serverName,
 *		boolean clientUsage, boolean truncateCertificatePath, CertificateMessage message) {
 * 	CertPath verifiedCertificate = ... verify certificate ...;
 * 	return new CertificateVerificationResult(cid, verifiedCertificate, null);
 * }
 * </pre>
 *
 * <p>
 * Asynchronous example returning the master secret:
 * </p>
 * 
 * <pre>
 * &#64;Override
 * public CertificateVerificationResult verifyCertificate(ConnectionId cid, ServerNames serverName,
 *		boolean clientUsage, boolean truncateCertificatePath, CertificateMessage message) {
 * 	
 * 		start ... verify certificate ... 
 * 			// calls processResult with verified certificate path asynchronous;
 * 		return null; // returns null for asynchronous processing
 * }
 * 
 * &#64;Override
 * public void setResultHandler(HandshakeResultHandler resultHandler) {
 * 		this.resultHandler = resultHandler;
 * }
 * 
 * 	private void verifyCertificateAsynchronous(ConnectionId cid, ServerNames serverName, boolean clientUsage,
 * 			boolean truncateCertificatePath, CertificateMessage message) {
 * 		// executed by different thread!
 * 		CertificateVerificationResult result = ... verify certificate ...
 * 		resultHandler.apply(result);
 * }
 * </pre>
 * 
 * @since 2.5
 */
public interface NewAdvancedCertificateVerifier {

	/**
	 * Get the list of supported certificate types in order of preference.
	 * 
	 * @return the list of supported certificate types.
	 * @since 3.0 (renamed from getSupportedCertificateType)
	 */
	List<CertificateType> getSupportedCertificateTypes();

	/**
	 * Validates the certificate provided by the the peer as part of the
	 * certificate message.
	 * 
	 * If a x509 certificate chain is provided in the certificate message,
	 * validate the chain and key usage. If a RawPublicKey certificate is
	 * provided, check, if this public key is trusted.
	 * 
	 * @param cid connection ID
	 * @param serverName indicated server names. May be {@code null}, if not
	 *            available or SNI is not enabled.
	 * @param remotePeer socket address of remote peer
	 * @param clientUsage indicator to check certificate usage. {@code true},
	 *            check key usage for client, {@code false} for server.
	 * @param verifySubject {@code true} to verify the certificate's subjects,
	 *            {@code false}, if not.
	 * @param truncateCertificatePath {@code true} truncate certificate path at
	 *            a trusted certificate before validation.
	 * @param message certificate message to be validated
	 * @return certificate verification result, or {@code null}, if result is
	 *         provided asynchronous.
	 * @since 3.0 (removed DTLSSession session, added remotePeer and
	 *        verifySubject)
	 */
	CertificateVerificationResult verifyCertificate(ConnectionId cid, ServerNames serverName,
			InetSocketAddress remotePeer, boolean clientUsage, boolean verifySubject, boolean truncateCertificatePath,
			CertificateMessage message);

	/**
	 * Return an list of certificate authorities which are trusted
	 * for authenticating peers.
	 * 
	 * @return a non-null (possibly empty) list of accepted CA issuers.
	 */
	List<X500Principal> getAcceptedIssuers();

	/**
	 * Set the handler for asynchronous handshake results.
	 * 
	 * Called during initialization of the {@link DTLSConnector}. Synchronous
	 * implementations may just ignore this using an empty implementation.
	 * 
	 * @param resultHandler handler for asynchronous master secret results. This
	 *            handler MUST NOT be called from the thread calling
	 *            {@link #verifyCertificate(ConnectionId, ServerNames, InetSocketAddress, boolean, boolean, boolean, CertificateMessage)},
	 *            instead just return the result there.
	 */
	void setResultHandler(HandshakeResultHandler resultHandler);

}
