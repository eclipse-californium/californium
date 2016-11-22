/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import java.security.Principal;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.eclipse.californium.elements.tcp.ConnectorTestUtil.SSLTestContext;
import org.eclipse.californium.elements.util.SslContextLoggingUtil;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;
import org.eclipse.californium.elements.util.SslDirectTrustContextUtil;

/**
 * Utils for TLS based connector tests using "direct-trust".
 */
public class DirectTrustConnectorTestUtil {

	public static final char[] SELF_SIGNED_KEY_STORE_PASSWORD = "selfPass".toCharArray();
	public static final String SELF_SIGNED_KEY_STORE_LOCATION = "certs/selfSignedKeyStore.jks";

	public static final String CLIENT_NAME_PATTERN = "client.*";

	public static final String SELF_SIGNED_SERVER_NAME = "cf-self-signed-server";
	public static final String SELF_SIGNED_CLIENT_NAME = "cf-self-signed-client-1";
	public static final String SELF_SIGNED_NO_TRUST_NAME = "cf-self-signed-client-2";
	public static final String SELF_SIGNED_CLIENT_NAME_PATTERN = "cf-self-signed-client-.*";

	public static SSLTestContext initializeDirectTrustedContext(String aliasCredentials, String aliasTrustsPattern)
			throws Exception {
		KeyManager[] keys = SslContextUtil.loadKeyManager(SslContextUtil.CLASSPATH_PROTOCOL
				+ ConnectorTestUtil.KEY_STORE_LOCATION, aliasCredentials, ConnectorTestUtil.KEY_STORE_PASSWORD,
				ConnectorTestUtil.KEY_STORE_PASSWORD);
		TrustManager[] trusts = SslDirectTrustContextUtil.loadDirectTrustManager(SslContextUtil.CLASSPATH_PROTOCOL
				+ ConnectorTestUtil.KEY_STORE_LOCATION, aliasTrustsPattern, ConnectorTestUtil.KEY_STORE_PASSWORD);

		Principal subjectDN = ConnectorTestUtil.getSubjectDN(keys, aliasCredentials);
		ConnectorTestUtil.log("keys ", keys);
		ConnectorTestUtil.log("trusts", trusts, true);

		keys = SslContextLoggingUtil.logging(keys, aliasCredentials);
		trusts = SslContextLoggingUtil.logging(trusts, aliasCredentials);

		SSLContext context = SSLContext.getInstance("TLS");
		context.init(keys, trusts, null);
		return new SSLTestContext(context, subjectDN);
	}

	public static SSLTestContext initializeSelfSignedDirectTrustedContext(String aliasCredentials,
			String aliasTrustsPattern) throws Exception {
		KeyManager[] keys = SslContextUtil.loadKeyManager(SslContextUtil.CLASSPATH_PROTOCOL
				+ SELF_SIGNED_KEY_STORE_LOCATION, aliasCredentials, SELF_SIGNED_KEY_STORE_PASSWORD,
				SELF_SIGNED_KEY_STORE_PASSWORD);
		TrustManager[] trusts = SslDirectTrustContextUtil.loadDirectTrustManager(SslContextUtil.CLASSPATH_PROTOCOL
				+ SELF_SIGNED_KEY_STORE_LOCATION, aliasTrustsPattern, SELF_SIGNED_KEY_STORE_PASSWORD);

		Principal subjectDN = ConnectorTestUtil.getSubjectDN(keys, aliasCredentials);
		ConnectorTestUtil.log("keys ", keys);
		ConnectorTestUtil.log("trusts", trusts, true);

		keys = SslContextLoggingUtil.logging(keys, aliasCredentials);
		trusts = SslContextLoggingUtil.logging(trusts, aliasCredentials);

		SSLContext context = SSLContext.getInstance("TLS");
		context.init(keys, trusts, null);
		return new SSLTestContext(context, subjectDN);
	}

	public static SSLTestContext initializeSelfSignedBorkenDirectTrustedContext(String aliasKey, String aliasChain,
			String aliasTrustsPattern) throws Exception {
		Credentials credentials = SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_PROTOCOL
				+ SELF_SIGNED_KEY_STORE_LOCATION, aliasKey, SELF_SIGNED_KEY_STORE_PASSWORD,
				SELF_SIGNED_KEY_STORE_PASSWORD);
		X509Certificate[] chain = SslContextUtil.loadCertificateChain(SslContextUtil.CLASSPATH_PROTOCOL
				+ SELF_SIGNED_KEY_STORE_LOCATION, aliasChain, SELF_SIGNED_KEY_STORE_PASSWORD);

		KeyManager[] keys = SslContextUtil.createKeyManager(aliasChain, credentials.getPrivateKey(), chain);
		TrustManager[] trusts = SslDirectTrustContextUtil.loadDirectTrustManager(SslContextUtil.CLASSPATH_PROTOCOL
				+ SELF_SIGNED_KEY_STORE_LOCATION, aliasTrustsPattern, SELF_SIGNED_KEY_STORE_PASSWORD);

		Principal subjectDN = chain[0].getSubjectX500Principal();
		ConnectorTestUtil.log("keys ", keys);
		ConnectorTestUtil.log("trusts", trusts, true);

		keys = SslContextLoggingUtil.logging(keys, aliasChain);
		trusts = SslContextLoggingUtil.logging(trusts, aliasChain);

		SSLContext context = SSLContext.getInstance("TLS");
		context.init(keys, trusts, null);
		return new SSLTestContext(context, subjectDN);
	}

	public static SSLTestContext initializeSelfSignedContext(String aliasCredentials, String aliasTrustsPattern)
			throws Exception {
		KeyManager[] keys = SslContextUtil.loadKeyManager(SslContextUtil.CLASSPATH_PROTOCOL
				+ SELF_SIGNED_KEY_STORE_LOCATION, aliasCredentials, SELF_SIGNED_KEY_STORE_PASSWORD,
				SELF_SIGNED_KEY_STORE_PASSWORD);
		TrustManager[] trusts = SslContextUtil.loadTrustManager(SslContextUtil.CLASSPATH_PROTOCOL
				+ SELF_SIGNED_KEY_STORE_LOCATION, aliasTrustsPattern, SELF_SIGNED_KEY_STORE_PASSWORD);

		Principal subjectDN = ConnectorTestUtil.getSubjectDN(keys, aliasCredentials);
		ConnectorTestUtil.log("keys ", keys);
		ConnectorTestUtil.log("trusts", trusts, true);

		keys = SslContextLoggingUtil.logging(keys, aliasCredentials);
		trusts = SslContextLoggingUtil.logging(trusts, aliasCredentials);

		SSLContext context = SSLContext.getInstance("TLS");
		context.init(keys, trusts, null);
		return new SSLTestContext(context, subjectDN);
	}

}
