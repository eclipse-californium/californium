/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 *******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;

import javax.crypto.SecretKey;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerName;
import org.eclipse.californium.scandium.util.ServerName.NameType;
import org.eclipse.californium.scandium.util.ServerNames;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class PskUtilTest {

	private static final String VIRTUAL_HOST = "californium";
	private static final InetSocketAddress LOCALHOST = new InetSocketAddress(InetAddress.getLoopbackAddress(), 5684);
	private static final ServerNames SERVER_NAMES = ServerNames
			.newInstance(ServerName.from(NameType.HOST_NAME, VIRTUAL_HOST.getBytes(ServerName.CHARSET)));
	private static final PskPublicInformation IDENTITY = new PskPublicInformation("me");
	private static final PskPublicInformation SCOPED_IDENTITY = new PskPublicInformation("cali.me");
	private static final SecretKey KEY = SecretUtil.create("secret".getBytes(), "PSK");
	private static final SecretKey SCOPED_KEY = SecretUtil.create("cali.secret".getBytes(), "PSK");

	private DTLSSession session;
	private DTLSSession sessionWithVirtualServer;
	private PskStore pskStore;
	private PskUtil util;

	@Before
	public void init() {
		pskStore = mock(PskStore.class);

		when(pskStore.getIdentity(LOCALHOST)).thenReturn(IDENTITY);
		when(pskStore.getKey(IDENTITY)).thenReturn(SecretUtil.create(KEY));
		when(pskStore.getIdentity(LOCALHOST, SERVER_NAMES)).thenReturn(SCOPED_IDENTITY);
		when(pskStore.getKey(SERVER_NAMES, SCOPED_IDENTITY)).thenReturn(SecretUtil.create(SCOPED_KEY));

		session = new DTLSSession(LOCALHOST);
		sessionWithVirtualServer = new DTLSSession(LOCALHOST);
		sessionWithVirtualServer.setHostName(VIRTUAL_HOST);
		sessionWithVirtualServer.setSniSupported(true);
	}

	@After
	public void cleanup() {
		SecretUtil.destroy(util);
	}

	@Test
	public void testClientGetPlainIdentity() throws HandshakeException {
		util = new PskUtil(false, session, pskStore);
		assertThat(util.getPskPublicIdentity(), is(IDENTITY));
		verify(pskStore, times(1)).getIdentity(LOCALHOST);
		verify(pskStore, never()).getIdentity((InetSocketAddress) anyObject(), (ServerNames) anyObject());
		verify(pskStore, times(1)).getKey(IDENTITY);
		verify(pskStore, never()).getKey((ServerNames) anyObject(), (PskPublicInformation) anyObject());
		SecretKey premasterSecret = util.generatePremasterSecretFromPSK(null);
		assertThat(premasterSecret, is(notNullValue()));
	}

	@Test
	public void testClientGetPlainIdentityWithVirtualServer() throws HandshakeException {
		util = new PskUtil(false, sessionWithVirtualServer, pskStore);
		assertThat(util.getPskPublicIdentity(), is(IDENTITY));
		verify(pskStore, times(1)).getIdentity(LOCALHOST);
		verify(pskStore, never()).getIdentity((InetSocketAddress) anyObject(), (ServerNames) anyObject());
		verify(pskStore, times(1)).getKey(IDENTITY);
		verify(pskStore, never()).getKey((ServerNames) anyObject(), (PskPublicInformation) anyObject());
		SecretKey premasterSecret = util.generatePremasterSecretFromPSK(null);
		assertThat(premasterSecret, is(notNullValue()));
	}

	@Test
	public void testClientGetSniIdentity() throws HandshakeException {
		util = new PskUtil(true, session, pskStore);
		assertThat(util.getPskPublicIdentity(), is(IDENTITY));
		verify(pskStore, times(1)).getIdentity(LOCALHOST);
		verify(pskStore, never()).getIdentity((InetSocketAddress) anyObject(), (ServerNames) anyObject());
		verify(pskStore, times(1)).getKey(IDENTITY);
		verify(pskStore, never()).getKey((ServerNames) anyObject(), (PskPublicInformation) anyObject());
		SecretKey premasterSecret = util.generatePremasterSecretFromPSK(null);
		assertThat(premasterSecret, is(notNullValue()));
	}

	@Test
	public void testClientGetSniIdentityWithVirtualServer() throws HandshakeException {
		util = new PskUtil(true, sessionWithVirtualServer, pskStore);
		assertThat(util.getPskPublicIdentity(), is(SCOPED_IDENTITY));
		verify(pskStore, times(1)).getIdentity(LOCALHOST, SERVER_NAMES);
		verify(pskStore, never()).getIdentity((InetSocketAddress) anyObject());
		verify(pskStore, times(1)).getKey(SERVER_NAMES, SCOPED_IDENTITY);
		verify(pskStore, never()).getKey((PskPublicInformation) anyObject());
		SecretKey premasterSecret = util.generatePremasterSecretFromPSK(null);
		assertThat(premasterSecret, is(notNullValue()));
	}

	@Test
	public void testServerGetPlainIdentity() throws HandshakeException {
		util = new PskUtil(false, session, pskStore, IDENTITY);
		assertThat(util.getPskPublicIdentity(), is(IDENTITY));
		verify(pskStore, never()).getIdentity((InetSocketAddress) anyObject());
		verify(pskStore, never()).getIdentity((InetSocketAddress) anyObject(), (ServerNames) anyObject());
		verify(pskStore, times(1)).getKey(IDENTITY);
		verify(pskStore, never()).getKey((ServerNames) anyObject(), (PskPublicInformation) anyObject());
		SecretKey premasterSecret = util.generatePremasterSecretFromPSK(null);
		assertThat(premasterSecret, is(notNullValue()));
	}

	@Test
	public void testServerGetPlainIdentityWithVirtualServer() throws HandshakeException {
		util = new PskUtil(false, sessionWithVirtualServer, pskStore, IDENTITY);
		assertThat(util.getPskPublicIdentity(), is(IDENTITY));
		verify(pskStore, never()).getIdentity((InetSocketAddress) anyObject());
		verify(pskStore, never()).getIdentity((InetSocketAddress) anyObject(), (ServerNames) anyObject());
		verify(pskStore, times(1)).getKey(IDENTITY);
		verify(pskStore, never()).getKey((ServerNames) anyObject(), (PskPublicInformation) anyObject());
		SecretKey premasterSecret = util.generatePremasterSecretFromPSK(null);
		assertThat(premasterSecret, is(notNullValue()));
	}

	@Test
	public void testServerGetSniIdentity() throws HandshakeException {
		util = new PskUtil(true, session, pskStore, IDENTITY);
		assertThat(util.getPskPublicIdentity(), is(IDENTITY));
		verify(pskStore, never()).getIdentity((InetSocketAddress) anyObject());
		verify(pskStore, never()).getIdentity((InetSocketAddress) anyObject(), (ServerNames) anyObject());
		verify(pskStore, times(1)).getKey(IDENTITY);
		verify(pskStore, never()).getKey((ServerNames) anyObject(), (PskPublicInformation) anyObject());
		SecretKey premasterSecret = util.generatePremasterSecretFromPSK(null);
		assertThat(premasterSecret, is(notNullValue()));
	}

	@Test
	public void testServerGetSniIdentityWithVirtualServer() throws HandshakeException {
		util = new PskUtil(true, sessionWithVirtualServer, pskStore, SCOPED_IDENTITY);
		assertThat(util.getPskPublicIdentity(), is(SCOPED_IDENTITY));
		verify(pskStore, never()).getIdentity((InetSocketAddress) anyObject());
		verify(pskStore, never()).getIdentity((InetSocketAddress) anyObject(), (ServerNames) anyObject());
		verify(pskStore, never()).getKey((PskPublicInformation) anyObject());
		verify(pskStore, times(1)).getKey(SERVER_NAMES, SCOPED_IDENTITY);
		SecretKey premasterSecret = util.generatePremasterSecretFromPSK(null);
		assertThat(premasterSecret, is(notNullValue()));
	}

	@Test
	public void testGeneratePremasterSecret() throws HandshakeException {
		util = new PskUtil(false, session, pskStore, IDENTITY);
		SecretKey premasterSecret = util.generatePremasterSecretFromPSK(null);
		assertThat(premasterSecret, is(notNullValue()));
		SecretKey premasterSecret2 = util.generatePremasterSecretFromPSK(null);
		assertThat(premasterSecret2, is(notNullValue()));
		assertArrayEquals(premasterSecret.getEncoded(), premasterSecret2.getEncoded());

		SecretKey premasterSecret3 = util.generatePremasterSecretFromPSK(KEY);
		assertThat(premasterSecret3, is(notNullValue()));
		SecretKey premasterSecret4 = util.generatePremasterSecretFromPSK(KEY);
		assertThat(premasterSecret4, is(notNullValue()));
		assertArrayEquals(premasterSecret3.getEncoded(), premasterSecret4.getEncoded());
		assertFalse(Arrays.equals(premasterSecret2.getEncoded(), premasterSecret4.getEncoded()));

		SecretKey premasterSecret5 = util.generatePremasterSecretFromPSK(SCOPED_KEY);
		assertThat(premasterSecret5, is(notNullValue()));
		SecretKey premasterSecret6 = util.generatePremasterSecretFromPSK(SCOPED_KEY);
		assertThat(premasterSecret6, is(notNullValue()));
		assertArrayEquals(premasterSecret5.getEncoded(), premasterSecret6.getEncoded());
		assertFalse(Arrays.equals(premasterSecret2.getEncoded(), premasterSecret6.getEncoded()));
		assertFalse(Arrays.equals(premasterSecret4.getEncoded(), premasterSecret6.getEncoded()));
	}
}
