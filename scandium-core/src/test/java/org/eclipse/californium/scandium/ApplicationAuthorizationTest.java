/*******************************************************************************
 * Copyright (c) 2018 - 2019 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial creation
 *                                                    Based on the original test
 *                                                    in DTLSConnectorTest.
 *                                                    Updated to use ConnectorHelper
 ******************************************************************************/
package org.eclipse.californium.scandium;

import static org.eclipse.californium.scandium.ConnectorHelper.SERVERNAME;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.util.Arrays;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.auth.ApplicationPrincipal;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.config.CertificateAuthenticationMode;
import org.eclipse.californium.elements.rule.LoggingRule;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.rule.TestTimeRule;
import org.eclipse.californium.elements.rule.ThreadsRule;
import org.eclipse.californium.elements.util.TestCondition;
import org.eclipse.californium.elements.util.TestConditionTools;
import org.eclipse.californium.scandium.ConnectorHelper.AlertCatcher;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.x509.AsyncCertificateVerifier;
import org.eclipse.californium.scandium.rule.DtlsNetworkRule;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/**
 * Verifies behavior of {@link DTLSConnector}.
 * <p>
 * Mainly contains integration test cases verifying the correct interaction
 * between a client and a server during handshakes with and without SNI.
 */
@RunWith(Parameterized.class)
@Category(Medium.class)
public class ApplicationAuthorizationTest {

	@ClassRule
	public static DtlsNetworkRule network = new DtlsNetworkRule(DtlsNetworkRule.Mode.DIRECT,
			DtlsNetworkRule.Mode.NATIVE);

	@ClassRule
	public static ThreadsRule cleanup = new ThreadsRule();

	private static final int CLIENT_CONNECTION_STORE_CAPACITY = 5;

	@Rule
	public TestTimeRule time = new TestTimeRule();

	@Rule
	public TestNameLoggerRule names = new TestNameLoggerRule();
	@Rule
	public LoggingRule logging = new LoggingRule();

	enum Mode {
		NONE, AUTHORIZE, REJECT
	}

	@Parameter(0)
	public Mode mode;

	@Parameters(name = "mode {0}")
	public static Iterable<Mode> setups() {
		return Arrays.asList(Mode.values());
	}

	DtlsConnectorConfig.Builder serverBuilder;
	ConnectorHelper serverHelper;

	AsyncCertificateVerifier serverVerifier;

	DtlsHealthLogger serverHealth;

	DtlsConnectorConfig.Builder clientBuilder;
	DTLSConnector client;
	AlertCatcher clientAlertCatcher;
	AsyncCertificateVerifier clientVerifier;
	DtlsConnectorConfig.Builder clientConfigBuilder;

	/**
	 * Sets up the fixture.
	 */
	@Before
	public void setUp() {

		clientAlertCatcher = new AlertCatcher();

		serverHelper = new ConnectorHelper(network);
		serverBuilder = serverHelper.serverBuilder;
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE)
		.set(DtlsConfig.DTLS_APPLICATION_AUTHORIZATION_TIMEOUT, 1, TimeUnit.SECONDS);

		clientBuilder = DtlsConnectorConfig.builder(network.createClientTestConfig());
	}

	/**
	 * Destroys the server and client.
	 */
	@After
	public void cleanUp() {
		if (serverHelper != null && serverHelper.server != null) {
			assertThat(serverHelper.server.isRunning(), is(true));
			try {
				// wait until no pending jobs left
				TestConditionTools.waitForCondition(6000, 100, TimeUnit.MILLISECONDS, new TestCondition() {

					@Override
					public boolean isFulFilled() throws IllegalStateException {
						return !serverHelper.server.updateHealth();
					}
				});
				TestConditionTools.assertStatisticCounter("jobs left", serverHealth, "pending in jobs", is(0L));
				TestConditionTools.assertStatisticCounter("jobs left", serverHealth, "pending out jobs", is(0L));
				TestConditionTools.assertStatisticCounter("jobs left", serverHealth, "pending handshake jobs", is(0L));
			} catch (InterruptedException e) {
			}
		}
		if (serverVerifier != null) {
			serverVerifier.shutdown();
			serverVerifier = null;
		}
		if (serverHelper != null) {
			if (serverHelper.server != null) {
				serverHelper.server.stop();
				ConnectorHelper.assertReloadConnections("server", serverHelper.server);
			}
			serverHelper.destroyServer();
			serverHelper = null;
		}
		if (clientVerifier != null) {
			clientVerifier.shutdown();
			clientVerifier = null;
		}
		if (client != null) {
			client.stop();
			ConnectorHelper.assertReloadConnections("client", client);
			client.destroy();
			client = null;
		}
	}

	private void startServer() throws IOException, GeneralSecurityException {

		DtlsConnectorConfig incompleteConfig = serverBuilder.getIncompleteConfig();

		if (incompleteConfig.get(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE) != CertificateAuthenticationMode.NONE) {
			if (incompleteConfig.getCertificateVerifier() == null) {
				serverVerifier = AsyncCertificateVerifier.builder().setTrustAllCertificates().setTrustAllRPKs().build();
				serverBuilder.setCertificateVerifier(serverVerifier);
				serverVerifier.setDelay(DtlsTestTools.DEFAULT_HANDSHAKE_RESULT_DELAY_MILLIS);
			}
		}
		serverHealth = new DtlsHealthLogger("server");
		serverBuilder.setHealthHandler(serverHealth);
		serverHelper.startServer();

	}

	private DTLSSession startClientRpk(String hostname) throws Exception {
		clientVerifier = AsyncCertificateVerifier.builder().setTrustAllRPKs().build();
		clientBuilder.setCertificateVerifier(clientVerifier);
		return startClient(hostname);
	}

	private DTLSSession startClientX509(String hostname) throws Exception {
		if (clientBuilder.getIncompleteConfig().getCertificateVerifier() == null) {
			clientVerifier = AsyncCertificateVerifier.builder().setTrustAllCertificates()
					.build();
			clientBuilder.setCertificateVerifier(clientVerifier);
		}
		return startClient(hostname);
	}

	private DTLSSession startClient(String hostname) throws Exception {
		InetSocketAddress clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
		clientBuilder.setAddress(clientEndpoint).setLoggingTag("client").set(DtlsConfig.DTLS_RECEIVER_THREAD_COUNT, 1)
				.set(DtlsConfig.DTLS_CONNECTOR_THREAD_COUNT, 1)
				.set(DtlsConfig.DTLS_MAX_CONNECTIONS, CLIENT_CONNECTION_STORE_CAPACITY);

		DtlsConnectorConfig clientConfig = clientBuilder.build();

		client = serverHelper.createClient(clientConfig);
		client.setAlertHandler(clientAlertCatcher);
		RawData raw = RawData.outbound("Hello World".getBytes(),
				new AddressEndpointContext(serverHelper.serverEndpoint, hostname, null), null, false);
		serverHelper.givenAnEstablishedSession(client, raw, true);
		final DTLSSession session = client.getSessionByAddress(serverHelper.serverEndpoint);
		assertThat(session, is(notNullValue()));
		return session;
	}

	@Test
	public void testRpkHandshakeApplicationAuthorized() throws Exception {
		startServer();
		startClientRpk(null);
		final EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();

		// client's principal
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));

		if (mode == Mode.AUTHORIZE) {
			Future<Boolean> future = serverHelper.server.authorize(endpointContext, ApplicationPrincipal.ANONYMOUS);
			assertThat(future.get(1000, TimeUnit.MILLISECONDS), is(true));
			principal = serverHelper.getServersClientIdentity(endpointContext);
			assertThat(principal, is(ApplicationPrincipal.ANONYMOUS));
			// second authorization is rejected.
			future = serverHelper.server.authorize(endpointContext, new ApplicationPrincipal("test", false));
			assertThat(future.get(1000, TimeUnit.MILLISECONDS), is(false));
			principal = serverHelper.getServersClientIdentity(endpointContext);
			assertThat(principal, is(ApplicationPrincipal.ANONYMOUS));
			
		} else if (mode == Mode.REJECT) {
			Future<Void> future = serverHelper.server.rejectAuthorization(endpointContext);
			future.get(1000, TimeUnit.MILLISECONDS);
			TestConditionTools.assertStatisticCounter(serverHealth, "application rejected authorizations", is(1L), 500,
					TimeUnit.MILLISECONDS);
		} else if (mode == Mode.NONE) {
			Thread.sleep(2000);
		}

		// still available after recent handshake timeout
		time.addTestTimeShift(CookieGenerator.COOKIE_LIFETIME_NANOS * 3, TimeUnit.NANOSECONDS);

		serverHelper.server.cleanupRecentHandshakes(0);
//		assertThat(serverHelper.server.cleanupRecentHandshakes(0), is(1));
		if (mode == Mode.NONE) {
			TestConditionTools.assertStatisticCounter(serverHealth, "application missing authorizations", is(1L), 500,
					TimeUnit.MILLISECONDS);
		}
		serverHelper.getServerConnection(endpointContext, mode == Mode.AUTHORIZE);
	}

	@Test
	public void testX509HandshakeApplicationAuthorized() throws Exception {
		startServer();
		startClientX509(SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();

		// client's principal
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));

		if (mode == Mode.AUTHORIZE) {
			Future<Boolean> future = serverHelper.server.authorize(endpointContext, ApplicationPrincipal.ANONYMOUS);
			future.get(1000, TimeUnit.MILLISECONDS);
			principal = serverHelper.getServersClientIdentity(endpointContext);
			assertThat(principal, is(ApplicationPrincipal.ANONYMOUS));
		} else if (mode == Mode.REJECT) {
			Future<Void> future = serverHelper.server.rejectAuthorization(endpointContext);
			future.get(1000, TimeUnit.MILLISECONDS);
			TestConditionTools.assertStatisticCounter(serverHealth, "application rejected authorizations", is(1L), 500,
					TimeUnit.MILLISECONDS);
		} else if (mode == Mode.NONE) {
			Thread.sleep(2000);
		}

		// still available after recent handshake timeout
		time.addTestTimeShift(CookieGenerator.COOKIE_LIFETIME_NANOS * 3, TimeUnit.NANOSECONDS);

		serverHelper.server.cleanupRecentHandshakes(0);
//		assertThat(serverHelper.server.cleanupRecentHandshakes(0), is(1));
		if (mode == Mode.NONE) {
			TestConditionTools.assertStatisticCounter(serverHealth, "application missing authorizations", is(1L), 500,
					TimeUnit.MILLISECONDS);
		}
		serverHelper.getServerConnection(endpointContext, mode == Mode.AUTHORIZE);
	}
}
