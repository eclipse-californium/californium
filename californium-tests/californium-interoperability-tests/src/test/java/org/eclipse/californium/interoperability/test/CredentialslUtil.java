/*******************************************************************************
 * Copyright (c) 2022 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - credentials moved from OpenSslUtil
 ******************************************************************************/
package org.eclipse.californium.interoperability.test;

/**
 * Utility for credentials.
 * 
 * @since 3.3
 */
public class CredentialslUtil {

	public static final String SERVER_CERTIFICATE = "server.pem";
	public static final String SERVER_RSA_CERTIFICATE = "serverRsa.pem";
	public static final String SERVER_EDDSA_CERTIFICATE = "serverEdDsa.pem";
	public static final String SERVER_CA_RSA_CERTIFICATE = "serverCaRsa.pem";

	public static final String CLIENT_CERTIFICATE = "client.pem";
	public static final String CLIENT_RSA_CERTIFICATE = "clientRsa.pem";
	public static final String CLIENT_EDDSA_CERTIFICATE = "clientEdDsa.pem";
	public static final String ROOT_CERTIFICATE = "rootTrustStore.pem";
	public static final String CA_CERTIFICATES = "caTrustStore.pem";
	public static final String CA_RSA_CERTIFICATES = "caRsaTrustStore.pem";
	public static final String CA_EDDSA_CERTIFICATES = "caEdDsaTrustStore.pem";
	public static final String TRUSTSTORE = "trustStore.pem";

	public static final String OPENSSL_PSK_IDENTITY = "Client_identity";
	public static final byte[] OPENSSL_PSK_SECRET = "secretPSK".getBytes();

}
