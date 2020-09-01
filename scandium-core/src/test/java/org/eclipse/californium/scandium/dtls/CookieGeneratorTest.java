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
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;

import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.rule.TestTimeRule;
import org.eclipse.californium.elements.runner.RepeatingTestRunner;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.TestScope;
import org.eclipse.californium.elements.util.TestThreadFactory;
import org.eclipse.californium.scandium.CookieGenerator;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tests verifying behavior of {@link CookieGenerator}.
 *
 */
@Category(Small.class)
@RunWith(RepeatingTestRunner.class)
public class CookieGeneratorTest {
	private static final Logger LOGGER = LoggerFactory.getLogger(CookieGeneratorTest.class);

	@Rule
	public TestTimeRule time = new TestTimeRule();

	CookieGenerator generator;
	InetSocketAddress peerAddress;
	InetSocketAddress peerAddress2;

	/**
	 * Sets up fixture.
	 */
	@Before
	public void setUp() {
		peerAddress = new InetSocketAddress("localhost", 5684);
		peerAddress2 = new InetSocketAddress("localhost", 5685);
		generator = new CookieGenerator();
	}

	@Test
	public void testCookieGeneratorGeneratesSameCookie() throws GeneralSecurityException {
		ClientHello clientHello = ClientHelloTest.createClientHello(peerAddress,
				Collections.singletonList(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256),
				SignatureAndHashAlgorithm.DEFAULT, Collections.<CertificateType> emptyList(),
				Collections.<CertificateType> emptyList(), Collections.singletonList(SupportedGroup.secp256r1));
		byte[] cookie1 = generator.generateCookie(clientHello);

		clientHello.setCookie(cookie1);

		byte[] cookie2 = generator.generateCookie(clientHello);
		assertArrayEquals(cookie1, cookie2);
	}

	@Test
	public void testCookieGeneratorGeneratesDifferentCookie() throws GeneralSecurityException, HandshakeException {
		ClientHello clientHello1 = ClientHelloTest.createClientHello(peerAddress,
				Collections.singletonList(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256),
				SignatureAndHashAlgorithm.DEFAULT, Collections.<CertificateType> emptyList(),
				Collections.<CertificateType> emptyList(), Collections.singletonList(SupportedGroup.secp256r1));
		byte[] cookie1 = generator.generateCookie(clientHello1);
		byte[] byteArray = clientHello1.fragmentToByteArray();
		ClientHello clientHello2 = ClientHello.fromReader(new DatagramReader(byteArray), peerAddress);
		clientHello2.setCookie(cookie1);

		byte[] cookie2 = generator.generateCookie(clientHello2);
		assertArrayEquals(cookie1, cookie2);

		ClientHello clientHello3 = ClientHello.fromReader(new DatagramReader(byteArray), peerAddress2);
		clientHello3.setCookie(cookie1);

		byte[] cookie3 = generator.generateCookie(clientHello3);
		assertFalse("byte arrays are equal!", Arrays.equals(cookie1, cookie3));
	}

	@Test
	public void testCookieGeneratorGeneratesDifferentCookieWhenPeriodExpires()
			throws GeneralSecurityException, HandshakeException {
		ClientHello clientHello1 = ClientHelloTest.createClientHello(peerAddress,
				Collections.singletonList(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256),
				SignatureAndHashAlgorithm.DEFAULT, Collections.<CertificateType> emptyList(),
				Collections.<CertificateType> emptyList(), Collections.singletonList(SupportedGroup.secp256r1));
		byte[] cookie1 = generator.generateCookie(clientHello1);
		time.addTestTimeShift(CookieGenerator.COOKIE_LIFE_TIME + 1000, TimeUnit.NANOSECONDS);
		byte[] cookie2 = generator.generateCookie(clientHello1);
		byte[] cookie3 = generator.generatePastCookie(clientHello1);

		assertFalse("byte arrays are equal!", Arrays.equals(cookie1, cookie2));
		assertArrayEquals(cookie1, cookie3);
	}

	@Test
	public void testCookieGeneratorGeneratesSameCookieMultiThreaded() throws GeneralSecurityException {
		final int LOOPS = TestScope.enableIntensiveTests() ? 20000 : 2000;
		final int COOKIE_USAGE = 100;
		final CountDownLatch done = new CountDownLatch(LOOPS);
		final ClientHello clientHello = ClientHelloTest.createClientHello(peerAddress,
				Collections.singletonList(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256),
				SignatureAndHashAlgorithm.DEFAULT, Collections.<CertificateType> emptyList(),
				Collections.<CertificateType> emptyList(), Collections.singletonList(SupportedGroup.secp256r1));
		final Queue<Bytes> cookies = new ConcurrentLinkedQueue<Bytes>();
		final Queue<Throwable> errors = new ConcurrentLinkedQueue<Throwable>();
		int numOfCookies = 1;
		ExecutorService service = ExecutorsUtil.newFixedThreadPool(64, new TestThreadFactory("Cookie-"));
		try {
			for (int i = 0; i < LOOPS; ++i) {
				final boolean flushTime = (i % COOKIE_USAGE) == (COOKIE_USAGE - 1);
				service.execute(new Runnable() {

					@Override
					public void run() {
						byte[] cookie;
						try {
							cookie = generator.generateCookie(clientHello);
							cookies.add(new Bytes(cookie, 32, false));
						} catch (GeneralSecurityException e) {
							errors.add(e);
						} catch (IllegalStateException e) {
							errors.add(e);
						}
						if (flushTime) {
							time.addTestTimeShift(CookieGenerator.COOKIE_LIFE_TIME + 1000, TimeUnit.NANOSECONDS);
						}
						done.countDown();
					}
				});
				if (flushTime) {
					++numOfCookies;
				}
			}
			done.await();
			Set<Bytes> set = new LinkedHashSet<>();
			for (Bytes cookie : cookies) {
				set.add(cookie);
			}
			LOGGER.warn("{} cookies of {}", set.size(), numOfCookies);
			assertThat("too many different cookies", set.size(), is(lessThanOrEqualTo(numOfCookies)));
			if (!errors.isEmpty()) {
				for (Throwable t : errors) {
					LOGGER.error("cookie failed!", t);
				}
				assertEquals("cookie errors occurred", 0, errors.size());
			}
		} catch (InterruptedException e) {
		} finally {
			service.shutdown();
		}
	}
}
