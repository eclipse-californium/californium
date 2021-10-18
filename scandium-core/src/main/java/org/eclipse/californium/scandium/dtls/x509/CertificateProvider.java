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
package org.eclipse.californium.scandium.dtls.x509;

import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.dtls.CertificateIdentityResult;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.CertificateKeyAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * Certificate identity provider.
 * <p>
 * One of the complex functions in (D)TLS is the negotiation of the crypto
 * parameters. That includes also to select the right certificate chain for the
 * proposed parameters of the client. The large variety of these parameters
 * makes it hard.
 * </p>
 * <p>
 * For CoAP this is simplified by
 * <a href="https://datatracker.ietf.org/doc/html/rfc7252#section-9.1" target=
 * "_blank">RFC 7252, 9.1 DTLS-Secured CoAP</a> using common sets of mandatory
 * supported crypto parameter values for the different security cases. That
 * makes it easier for clients to successfully negotiate a DTLS session and for
 * the server to offer the right selection of supported parameters.
 * </p>
 * <p>
 * If <a href="https://datatracker.ietf.org/doc/html/rfc7252#section-9.1.3.1"
 * target= "_blank">PSK</a> is used, the cipher suite
 * {@link CipherSuite#TLS_PSK_WITH_AES_128_CCM_8} is mandatory to implement.
 * </p>
 * <p>
 * If <a href="https://datatracker.ietf.org/doc/html/rfc7252#section-9.1.3.2"
 * target= "_blank">RPK</a> is used, the cipher suite
 * {@link CipherSuite#TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8} is mandatory to
 * implement. The Elliptic curve: secp256r1 (0x0017) and SHA256withECDSA are
 * also mandatory to support.
 * </p>
 * <p>
 * If <a href="https://datatracker.ietf.org/doc/html/rfc7252#section-9.1.3.3"
 * target= "_blank">X509</a> is used, the cipher suite
 * {@link CipherSuite#TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8} is mandatory to
 * implement. The Elliptic curve: secp256r1 (0x0017) and SHA256withECDSA are
 * also mandatory to support.
 * </p>
 * <p>
 * For simple setups {@link SingleCertificateProvider} will do the job. But for
 * several reason, the simple world of CoAP doesn't always fit into reality. On
 * the "old" side, some certificates on the path may be RSA based, on the "new"
 * Ed25519/Ed448 may be preferred. With that, it starts to get complex again,
 * and a server may require more different certificate paths to support
 * different clients. This provider interface helps to overcome this. It enables
 * to select the used certificates based on the related crypto parameter, server
 * name, and issuer.
 * </p>
 * <p>
 * Using x509 comes also with some more asymmetry: to use a certificate chain
 * for authentication, the sending peer is only required to support signing for
 * the node certificate's public key. For the all the issuer signatures the
 * support is only relevant for the receiving side. Californium's default
 * configuration implementation does always a full check, regardless of only
 * sending the certificates.
 * </p>
 * 
 * @since 3.0
 */
public interface CertificateProvider {

	/**
	 * Get the list of supported certificate key algorithms.
	 * 
	 * @return the list of supported certificate key algorithms.
	 */
	List<CertificateKeyAlgorithm> getSupportedCertificateKeyAlgorithms();

	/**
	 * Get the list of supported certificate types in order of preference.
	 * 
	 * @return the list of supported certificate types.
	 */
	List<CertificateType> getSupportedCertificateTypes();

	/**
	 * Get the certificate identity.
	 * 
	 * If multiple certificate identities are matching the criteria, the order
	 * of the signature and hash algorithms should be used to select the one to
	 * be used for the handshake. If lists are {@code null} or empty, it's not
	 * used to chose a certificate identity.
	 * 
	 * @param cid connection ID
	 * @param client {@code true}, for client side certificates, {@code false},
	 *            for server side certificates.
	 * @param issuers list of trusted issuers. May be {@code null} or empty.
	 * @param serverNames indicated server names. May be {@code null} or empty,
	 *            if not available or SNI is not enabled.
	 * @param certificateKeyAlgorithms list of list of certificate key
	 *            algorithms to select a node's certificate. May be {@code null}
	 *            or empty.
	 * @param signatureAndHashAlgorithms signatures and hash Algorithms. May be
	 *            {@code null} or empty.
	 * @param curves ec-curves (supported groups). May be {@code null} or empty.
	 * @return certificate identity result, or {@code null}, if result is
	 *         provided asynchronous.
	 */
	CertificateIdentityResult requestCertificateIdentity(ConnectionId cid, boolean client, List<X500Principal> issuers,
			ServerNames serverNames, List<CertificateKeyAlgorithm> certificateKeyAlgorithms,
			List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms, List<SupportedGroup> curves);

	/**
	 * Set the handler for asynchronous handshake results.
	 * 
	 * Called during initialization of the {@link DTLSConnector}. Synchronous
	 * implementations may just ignore this using an empty implementation.
	 * 
	 * @param resultHandler handler for asynchronous master secret results. This
	 *            handler MUST NOT be called from the thread calling
	 *            {@link #requestCertificateIdentity(ConnectionId, boolean, List, ServerNames, List, List, List)},
	 *            instead just return the result there.
	 */
	void setResultHandler(HandshakeResultHandler resultHandler);

}
