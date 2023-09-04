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
 *    Achim Kraus (Bosch.IO GmbH) - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.interoperability.test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;
import org.eclipse.californium.scandium.ConnectorHelper;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConfig.DtlsRole;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.SingleNodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedSinglePskStore;
import org.eclipse.californium.scandium.dtls.x509.SingleCertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.StaticNewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.StaticNewAdvancedCertificateVerifier.Builder;

/**
 * Connector utility.
 * 
 * Build and configure {@link DTLSConnector}.
 */
public class ConnectorUtil {

	public static final int PORT = 5684;

	public static final long HANDSHAKE_TIMEOUT_MILLIS = 4000;

	private static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	private static final String EDDSA_KEY_STORE_LOCATION = "certs/eddsaKeyStore.jks";
	private static final char[] TRUST_STORE_PASSWORD = "rootPass".toCharArray();
	private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";
	private static final String CLIENT_NAME = "client";
	private static final String SERVER_NAME = "server";
	public static final String CLIENT_RSA_NAME = "clientrsa";
	public static final String SERVER_RSA_NAME = "serverrsa";
	public static final String CLIENT_EDDSA_NAME = "clienteddsa";
	public static final String SERVER_EDDSA_NAME = "servereddsa";
	public static final String SERVER_CA_RSA_NAME = "servercarsa";
	public static final String TRUST_CA = "ca";
	public static final String TRUST_ROOT = "root";

	static {
		DtlsConfig.register();
	}

	/**
	 * Alert catcher.
	 */
	private ConnectorHelper.AlertCatcher alertCatcher = new ConnectorHelper.AlertCatcher();
	/**
	 * DTLS connector.
	 */
	private DTLSConnector connector;
	/**
	 * Credentials for ECDSA base cipher suites.
	 */
	private Credentials credentials;
	/**
	 * Specific credentials for ECDSA base cipher suites to be used by the next test.
	 */
	private Credentials nextCredentials;
	/**
	 * Next test uses anonymous peer.
	 */
	private boolean nextAnonymous;
	/**
	 * Specific certificate types to be used by the next test.
	 */
	private CertificateType[] nextCertificateTypes;
	private Certificate[] trustCa;
	private Certificate[] trustRoot;

	/**
	 * Create new utility instance.
	 * 
	 * @param client {@code true} to use client credentials, {@code false}, for
	 *            server credentials.
	 */
	public ConnectorUtil(boolean client) {
		try {
			credentials = SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION,
					client ? CLIENT_NAME : SERVER_NAME, KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
			trustCa = SslContextUtil.loadTrustedCertificates(SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION,
					TRUST_CA, TRUST_STORE_PASSWORD);
			trustRoot = SslContextUtil.loadTrustedCertificates(SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION,
					TRUST_ROOT, TRUST_STORE_PASSWORD);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void loadCredentials(String alias) {
		try {
			nextAnonymous = false;
			nextCredentials = SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, alias,
					KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
			fail(alias + ": " + e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			fail(alias + ": " + e.getMessage());
		}
	}

	public void loadEdDsaCredentials(String alias) {
		try {
			nextAnonymous = false;
			nextCredentials = SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + EDDSA_KEY_STORE_LOCATION,
					alias, KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
			fail(alias + ": " + e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			fail(alias + ": " + e.getMessage());
		}
	}

	public void setAnonymous() {
		nextAnonymous = true;
	}

	public void setCertificateTypes(CertificateType... types) {
		nextCertificateTypes = types;
	}

	/**
	 * Shutdown the connector.
	 */
	public void shutdown() {
		if (connector != null) {
			connector.destroy();
			connector = null;
		}
	}

	/**
	 * Build connector.
	 * 
	 * @param bind address to bind connector to
	 * @param trust alias of trusted certificate, or {@code null} to trust all
	 *            received certificates.
	 * @param cipherSuites cipher suites to support.
	 */
	public void build(InetSocketAddress bind, String trust, CipherSuite... cipherSuites) {
		build(bind, null, trust, cipherSuites);
	}

	/**
	 * Build connector.
	 * 
	 * @param bind address to bind connector to
	 * @param dtlsBuilder preconfigured dtls builder. Maybe {@code null}.
	 * @param trust alias of trusted certificate, or {@code null} to trust all
	 *            received certificates.
	 * @param cipherSuites cipher suites to support.
	 */
	public void build(InetSocketAddress bind, DtlsConnectorConfig.Builder dtlsBuilder, String trust,
			CipherSuite... cipherSuites) {
		List<CipherSuite> suites = Arrays.asList(cipherSuites);
		if (dtlsBuilder == null) {
			dtlsBuilder = DtlsConnectorConfig.builder(new Configuration());
		}
		dtlsBuilder.set(DtlsConfig.DTLS_ADDITIONAL_ECC_TIMEOUT, 1000, TimeUnit.MILLISECONDS)
				.set(DtlsConfig.DTLS_RETRANSMISSION_TIMEOUT, 1000, TimeUnit.MILLISECONDS)
				.set(DtlsConfig.DTLS_RECEIVER_THREAD_COUNT, 2)
				.set(DtlsConfig.DTLS_CONNECTOR_THREAD_COUNT, 2)
				.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false)
				.setAddress(bind)
				.setConnectionIdGenerator(new SingleNodeConnectionIdGenerator(6));
		if (CipherSuite.containsPskBasedCipherSuite(suites)) {
			dtlsBuilder.setAdvancedPskStore(
					new AdvancedSinglePskStore(CredentialslUtil.OPENSSL_PSK_IDENTITY, CredentialslUtil.OPENSSL_PSK_SECRET));
		}
		if (CipherSuite.containsCipherSuiteRequiringCertExchange(suites)) {
			if (nextAnonymous) {
				nextAnonymous = false;
				dtlsBuilder.set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY);
			} else if ((credentials != null || nextCredentials != null)
					&& dtlsBuilder.getIncompleteConfig().getCertificateIdentityProvider() == null) {
				Credentials credentials = nextCredentials != null ? nextCredentials : this.credentials;
				SingleCertificateProvider provider;
				if (nextCertificateTypes == null) {
					provider = new SingleCertificateProvider(credentials.getPrivateKey(),
							credentials.getCertificateChain(), CertificateType.X_509, CertificateType.RAW_PUBLIC_KEY);
				} else {
					provider = new SingleCertificateProvider(credentials.getPrivateKey(),
							credentials.getCertificateChain(), nextCertificateTypes);
					nextCertificateTypes = null;
				}
				dtlsBuilder.setCertificateIdentityProvider(provider);
			}
			if (dtlsBuilder.getIncompleteConfig().getAdvancedCertificateVerifier() == null) {
				Builder builder = StaticNewAdvancedCertificateVerifier.builder();
				if (TRUST_CA.equals(trust)) {
					builder.setTrustedCertificates(trustCa);
				} else if (TRUST_ROOT.equals(trust)) {
					builder.setTrustedCertificates(trustRoot);
				} else {
					builder.setTrustAllCertificates();
				}
				builder.setTrustAllRPKs();
				dtlsBuilder.setAdvancedCertificateVerifier(builder.build());
			}
		}
		dtlsBuilder.set(DtlsConfig.DTLS_CIPHER_SUITES, suites);
		connector = new DTLSConnector(dtlsBuilder.build());
		alertCatcher.resetEvent();
		connector.setAlertHandler(alertCatcher);
		nextCredentials = null;
	}

	/**
	 * Get connector.
	 * 
	 * @return connector
	 */
	public Connector getConnector() {
		return connector;
	}

	/**
	 * Get alert catcher for connector.
	 * 
	 * @return alert catcher
	 * @since 3.0
	 */
	public ConnectorHelper.AlertCatcher getAlertCatcher() {
		return alertCatcher;
	}

	/**
	 * Assert, that the alert is exchanged.
	 * 
	 * @param timeout timeout in milliseconds
	 * @param expected expected alert
	 * 
	 * @throws InterruptedException if waiting for the alert is interrupted.
	 * @since 3.0
	 */
	public void assertAlert(long timeout, AlertMessage expected) throws InterruptedException {
		AlertMessage alert = getAlertCatcher().waitForEvent(timeout, TimeUnit.MILLISECONDS);
		assertThat("received alert", alert, is(expected));
		getAlertCatcher().resetEvent();
	}

	/**
	 * Assert, that either no or only one of the expected alerts is received.
	 * 
	 * @param expectedAlerts expected alerts. Default is CLOSE_NOTIFY.
	 * @sine 3.0
	 */
	public void assertNoUnexpectedAlert(AlertMessage... expectedAlerts) {
		if (expectedAlerts == null || expectedAlerts.length == 0) {
			expectedAlerts = new AlertMessage[] { new AlertMessage(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY) };
		}
		AlertMessage alert = getAlertCatcher().getEvent();
		if (alert != null) {
			getAlertCatcher().resetEvent();
			StringBuffer description = new StringBuffer();
			description.append(alert.getLevel()).append("/").append(alert.getDescription())
					.append(" is not of expected ");
			for (AlertMessage expected : expectedAlerts) {
				if (expected.equals(alert)) {
					return;
				}
				description.append(expected.getLevel()).append("/").append(expected.getDescription()).append(", ");
			}
			description.setLength(description.length() - 1);
			fail(description.toString());
		}
	}
}
