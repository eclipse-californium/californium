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
package org.eclipse.californium.elements.config;

/**
 * Certificate authentication mode of other peer.
 * 
 * Used on the server-side to request a client to authenticate by a certificate.
 * On the client-side only {@link #NONE} or {@link #NEEDED} is supported
 * depending on the used cipher suite.
 * 
 * @since 3.0
 */
public enum CertificateAuthenticationMode {

	/**
	 * Don't use a certificate for authentication.
	 * 
	 * On server side, don't request a client certificate. Considered to
	 * authenticate using an other mechanism.
	 */
	NONE(false),
	/**
	 * Use a certificate for optional authentication.
	 * 
	 * Don't fail on an empty certificate, but it is considered to authenticate
	 * using an other mechanism.
	 * 
	 * On server side, request a client certificate.
	 */
	WANTED(true),
	/**
	 * Use a certificate for authentication.
	 * 
	 * Fail on an empty certificate.
	 * 
	 * On server side, request a client certificate.
	 */
	NEEDED(true);

	/**
	 * On server-side use a Certificate Request for this authentication mode.
	 * 
	 * @see <a href="https://tools.ietf.org/html/rfc5246#section-7.4.4" target=
	 *      "_blank">RFC 5246, 7.4.4. Certificate Request</a>
	 */
	private final boolean useCertificateRequest;

	/**
	 * Create client authentication mode
	 * 
	 * @param useCertificateRequest {@code true}, if a certificate is requested,
	 *            {@code false}, otherwise.
	 */
	CertificateAuthenticationMode(boolean useCertificateRequest) {
		this.useCertificateRequest = useCertificateRequest;
	}

	/**
	 * Gets usage of Certificate Request on server-side.
	 * 
	 * @return {@code true}, if a Certificate Request is used, {@code false}, if
	 *         not
	 * @see <a href="https://tools.ietf.org/html/rfc5246#section-7.4.4" target=
	 *      "_blank">RFC 5246, 7.4.4. Certificate Request</a>
	 */
	public boolean useCertificateRequest() {
		return useCertificateRequest;
	}
}
