/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creator
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Random;

import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.auth.PreSharedKeyIdentity;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class DTLSSessionTest {

	static final int DEFAULT_MAX_FRAGMENT_LENGTH = 16384; //2^14 as defined in DTLS 1.2 spec
	private static final Random RANDOM = new Random();
	DTLSSession session;

	@Before
	public void setUp() throws Exception {
		session = newEstablishedServerSession(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CertificateType.X_509);
	}

	@Test
	public void testDefaultMaxFragmentLengthCompliesWithSpec() {
		// when instantiating a default server session
		session = new DTLSSession();

		// then the max fragment size is as specified in DTLS spec
		assertThat(session.getMaxFragmentLength(), is(DEFAULT_MAX_FRAGMENT_LENGTH));
	}

	@Test
	public void testSessionCanBeResumedFromSessionTicket() throws GeneralSecurityException {
		// GIVEN a session ticket for an established server session
		session = newEstablishedServerSession(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CertificateType.RAW_PUBLIC_KEY);
		SessionTicket ticket = session.getSessionTicket();

		// WHEN creating a new session to be resumed from the ticket
		DTLSSession sessionToResume = new DTLSSession(session.getSessionIdentifier(), ticket);

		// THEN the new session contains all relevant pending state to perform an abbreviated handshake
		assertThatSessionsHaveSameRelevantPropertiesForResumption(sessionToResume, session);
	}

	@Test
	public void testSessionWithServerNamesCanBeResumedFromSessionTicket() throws GeneralSecurityException {
		// GIVEN a session ticket for an established server session
		session = newEstablishedServerSession(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CertificateType.RAW_PUBLIC_KEY);
		session.setHostName("test");
		SessionTicket ticket = session.getSessionTicket();

		// WHEN creating a new session to be resumed from the ticket
		DTLSSession sessionToResume = new DTLSSession(session.getSessionIdentifier(), ticket);

		// THEN the new session contains all relevant pending state to perform an abbreviated handshake
		assertThatSessionsHaveSameRelevantPropertiesForResumption(sessionToResume, session);
	}

	@Test
	public void testSessionCanBeResumedFromSerializedSessionTicket() throws GeneralSecurityException {
		// GIVEN a session ticket for an established server session
		session = newEstablishedServerSession(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CertificateType.RAW_PUBLIC_KEY);
		SessionTicket ticket = serialize(session.getSessionTicket());

		// WHEN creating a new session to be resumed from the ticket
		DTLSSession sessionToResume = new DTLSSession(session.getSessionIdentifier(), ticket);

		// THEN the new session contains all relevant pending state to perform an abbreviated handshake
		assertThatSessionsHaveSameRelevantPropertiesForResumption(sessionToResume, session);
	}

	@Test
	public void testSessionWithServerNamesCanBeResumedFromSerializedSessionTicket() throws GeneralSecurityException {
		// GIVEN a session ticket for an established server session
		session = newEstablishedServerSession(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CertificateType.RAW_PUBLIC_KEY);
		session.setHostName("test");
		SessionTicket ticket = serialize(session.getSessionTicket());

		// WHEN creating a new session to be resumed from the ticket
		DTLSSession sessionToResume = new DTLSSession(session.getSessionIdentifier(), ticket);

		// THEN the new session contains all relevant pending state to perform an abbreviated handshake
		assertThatSessionsHaveSameRelevantPropertiesForResumption(sessionToResume, session);
	}

	@Test
	public void testReloadEcdsaSession() throws GeneralSecurityException {
		// GIVEN a session ticket for an established server session
		session = newEstablishedServerSession(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CertificateType.RAW_PUBLIC_KEY);
		session.setHostName("test");

		DTLSSession session2 = reload(session);
		assertThat(session2, is(session));
	}

	@Test
	public void testReloadPskSession() throws GeneralSecurityException {
		// GIVEN a session ticket for an established server session
		session = newEstablishedServerSession(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8, CertificateType.RAW_PUBLIC_KEY);
		session.setHostName("test");

		DTLSSession session2 = reload(session);
		assertThat(session2, is(session));
	}

	@Test
	public void testReloadEcdsaEd25519Session() throws GeneralSecurityException {
		// GIVEN a session ticket for an established server session
		session = newEstablishedServerSession(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CertificateType.RAW_PUBLIC_KEY);
		session.setHostName("test");
		session.setSignatureAndHashAlgorithm(SignatureAndHashAlgorithm.INTRINSIC_WITH_ED25519);

		DTLSSession session2 = reload(session);
		assertThat(session2, is(session));
	}

	public static void assertThatSessionsHaveSameRelevantPropertiesForResumption(DTLSSession sessionToResume, DTLSSession establishedSession) {
		assertThat(sessionToResume.getSessionIdentifier(), is(establishedSession.getSessionIdentifier()));
		assertThat(sessionToResume.getCipherSuite(), is(establishedSession.getCipherSuite()));
		assertThat(sessionToResume.getCompressionMethod(), is(establishedSession.getCompressionMethod()));
		assertThat(sessionToResume.getMasterSecret(), is(establishedSession.getMasterSecret()));
		assertThat(sessionToResume.getPeerIdentity(), is(establishedSession.getPeerIdentity()));
		assertThat(sessionToResume.getServerNames(), is(establishedSession.getServerNames()));
	}

	public static DTLSSession newEstablishedServerSession(CipherSuite cipherSuite, CertificateType type) {

		DTLSSession session = new DTLSSession();
		session.setSessionIdentifier(new SessionId());
		session.setCipherSuite(cipherSuite);
		session .setCompressionMethod(CompressionMethod.NULL);
		session.setReceiveCertificateType(type);
		session.setSendCertificateType(type);
		session.setMasterSecret(new SecretKeySpec(getRandomBytes(48), "MAC"));
		if (cipherSuite.isPskBased()) {
			session.setPeerIdentity(new PreSharedKeyIdentity("client_identity"));
		} else {
			X509Certificate[] chain = DtlsTestTools.getServerCertificateChain();
			if (type == CertificateType.RAW_PUBLIC_KEY) {
				session.setPeerIdentity(new RawPublicKeyIdentity(chain[0].getPublicKey()));
			} else {
				session.setPeerIdentity(X509CertPath.fromCertificatesChain(chain));
			}
		}
		return session;
	}

	private static DTLSSession reload(DTLSSession context) {
		DatagramWriter writer = new DatagramWriter();
		context.write(writer);
		DatagramReader reader = new DatagramReader(writer.toByteArray());
		return DTLSSession.fromReader(reader);
	}

	private static byte[] getRandomBytes(int length) {
		byte[] result = new byte[length];
		RANDOM.nextBytes(result);
		return result;
	}
	
	private static SessionTicket serialize(SessionTicket ticket) {
		DatagramWriter writer = new DatagramWriter(true);
		ticket.encode(writer);
		byte[] ticketBytes = writer.toByteArray();
		DatagramReader reader = new DatagramReader(ticketBytes);
		SessionTicket result = SessionTicket.decode(reader);
		Bytes.clear(ticketBytes);
		writer.close();
		return result;
	}

}
