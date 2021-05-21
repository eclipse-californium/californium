/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assume.assumeTrue;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.cipher.CbcBlockCipher;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.InvalidMacException;
import org.eclipse.californium.scandium.dtls.cipher.RandomManager;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/**
 * This test is intended ensure similar calculation times for CBC verification
 * of invalid records.
 * 
 * It copies code from {@link Record}, because it tests a process-stage, which
 * is not required separately outside this test. The test is marked with
 * {@code @Ignore}, because it uses excessive calculation time! For now, please
 * run it manually as application.
 * 
 * Test idea:
 * 
 * <a href="https://www.isg.rhul.ac.uk/tls/TLStiming.pdf" target="_blank"> Lucky
 * Thirteen:Breaking the TLS and DTLS Record Protocols</a>
 * 
 * Lucky 13 attacks claims to be able to use "timing side channel" in order to
 * attack CBC implementations. A real attack would be also faced timing issues
 * of the ip-message-transmission and/or timing differences of the execution
 * machine, maybe by multiple processors or multiple threads. Usually it's
 * claimed, that these time variants could be filtered.
 * 
 * This test only focus in the "record verification" part after the decryption.
 * According the document, this part is the root, where wrong implementations
 * opens a "timing side channel" for attackers (as scandium does!). Therefore
 * this test creates records and manipulates padding length bytes to see, if
 * that results in different calculation times. Unfortunately, java blurrs the
 * times very much. To have usefull result, each test has to be repeated
 * multiple times (see {@link #LOOPS}). Though timing differences may have other
 * causes, that test is also repeated using just alway the proper padding length
 * byte to measure also the usual timing difference of each execution not caused
 * by the "timing side channel".
 * 
 * Results: they vary from test run to test run.
 * 
 * <pre>
 * HmacSHA256-MAC none compen.-44-67-same:  921[146] <  949 < 1039[176]:  98
 * HmacSHA256-MAC none compen.-41-70-same:  770[153] <  795 <  890[045]: 102
 * HmacSHA256-MAC none compen.-45-66-same:  923[032] <  949 < 1055[076]: 114
 * HmacSHA256-MAC none compen.-45-02-same:  922[168] <  940 < 1057[109]: 123
 * HmacSHA256-MAC none compen.-44-03-same:  921[078] <  948 < 1067[175]: 127
 * HmacSHA256-MAC compensation-44-67-all*: 1148[108] < 1186 < 1307[175]: 128
 * HmacSHA256-MAC none compen.-40-71-same:  770[175] <  795 <  916[094]: 129
 * HmacSHA256-MAC compensation-43-04-all*: 1002[090] < 1044 < 1165[123]: 131
 * HmacSHA256-MAC none compen.-43-04-same:  922[171] <  944 < 1072[217]: 135
 * HmacSHA256-MAC compensation-40-07-all*:  995[019] < 1042 < 1167[028]: 136
 * HmacSHA256-MAC compensation-43-68-same: 1164[015] < 1200 < 1340[060]: 148
 * HmacSHA256-MAC none compen.-40-07-same:  771[004] <  795 <  940[245]: 154
 * HmacSHA256-MAC compensation-44-67-same: 1163[185] < 1199 < 1349[251]: 156
 * HmacSHA256-MAC none compen.-43-68-same:  924[199] <  950 < 1100[083]: 159
 * HmacSHA256-MAC compensation-44-03-same: 1010[028] < 1045 < 1202[155]: 164
 * HmacSHA256-MAC compensation-40-71-same: 1173[072] < 1212 < 1368[128]: 164
 * HmacSHA256-MAC compensation-45-66-same: 1166[011] < 1204 < 1367[108]: 167
 * HmacSHA256-MAC compensation-41-70-same: 1170[153] < 1212 < 1371[163]: 169
 * HmacSHA256-MAC compensation-45-02-same: 1004[184] < 1040 < 1202[121]: 171
 * HmacSHA256-MAC compensation-42-05-all*: 1002[242] < 1042 < 1206[034]: 171
 * HmacSHA256-MAC compensation-41-70-all*: 1147[039] < 1192 < 1356[110]: 173
 * HmacSHA256-MAC none compen.-42-05-same:  769[142] <  791 <  956[074]: 174
 * HmacSHA256-MAC compensation-40-71-all*: 1150[018] < 1189 < 1362[134]: 181
 * HmacSHA256-MAC compensation-44-03-all*:  999[252] < 1043 < 1219[209]: 186
 * HmacSHA256-MAC none compen.-41-06-same:  773[046] <  796 <  973[106]: 187
 * HmacSHA256-MAC compensation-45-02-all*: 1000[006] < 1040 < 1220[095]: 190
 * HmacSHA256-MAC compensation-43-04-same: 1008[212] < 1044 < 1229[161]: 192
 * HmacSHA256-MAC compensation-43-68-all*: 1149[007] < 1180 < 1368[120]: 194
 * HmacSHA256-MAC compensation-45-66-all*: 1152[105] < 1192 < 1379[250]: 194
 * HmacSHA256-MAC compensation-40-07-same: 1010[004] < 1048 < 1245[081]: 203
 * HmacSHA256-MAC compensation-42-69-all*: 1156[110] < 1194 < 1410[138]: 223
 * HmacSHA256-MAC compensation-42-69-same: 1167[226] < 1207 < 1432[237]: 233
 * HmacSHA256-MAC none compen.-42-69-same:  769[119] <  796 < 1022[222]: 234
 * HmacSHA256-MAC compensation-42-05-same: 1016[029] < 1052 < 1279[137]: 235
 * HmacSHA256-MAC compensation-41-06-same: 1017[113] < 1049 < 1288[192]: 245
 * HmacSHA256-MAC compensation-41-06-all*: 1008[145] < 1046 < 1284[204]: 247
 * HmacSHA256-MAC none compen.-40-07-all*:  355[088] <  468 <  938[004]: 547
 * HmacSHA256-MAC none compen.-42-05-all*:  353[244] <  468 <  953[003]: 559
 * HmacSHA256-MAC none compen.-41-06-all*:  354[254] <  466 <  953[000]: 568
 * HmacSHA256-MAC none compen.-44-03-all*:  349[201] <  459 <  952[004]: 569
 * HmacSHA256-MAC none compen.-45-02-all*:  351[177] <  462 <  971[003]: 586
 * HmacSHA256-MAC none compen.-43-04-all*:  354[189] <  465 < 1080[004]: 697
 * HmacSHA256-MAC none compen.-41-70-all*:  355[149] <  603 < 1108[001]: 702
 * HmacSHA256-MAC none compen.-40-71-all*:  350[206] <  603 < 1108[000]: 706
 * HmacSHA256-MAC none compen.-43-68-all*:  349[213] <  598 < 1110[004]: 708
 * HmacSHA256-MAC none compen.-45-66-all*:  352[215] <  604 < 1128[000]: 719
 * HmacSHA256-MAC none compen.-42-69-all*:  348[180] <  597 < 1123[001]: 725
 * HmacSHA256-MAC none compen.-44-67-all*:  348[255] <  603 < 1153[000]: 747
 * (overall 47 min.)
 * </pre>
 * 
 * <table summary="Explanation">
 * <tr>
 * <td>MAC compensation</td>
 * <td>verification with MAC compensation</td>
 * </tr>
 * <tr>
 * <td>MAC none compen.</td>
 * <td>verification without MAC compensation (old implementation)</td>
 * </tr>
 * <tr>
 * <td>same</td>
 * <td>always use the same, proper padding length byte</td>
 * </tr>
 * <tr>
 * <td>all*</td>
 * <td>use all 256 values for the padding length byte</td>
 * </tr>
 * </table>
 * 
 * Summarize: The old verification implementation without MAC compensation shows
 * a clear timing differences for "all*". The other benchmarks show smaller
 * differences, and it seems to be not related to "same" or "all*".
 * 
 * Remark: This test contains some more stuff; different padding operators and
 * different statistic functions. Feel free to create your own benchmarks!
 */
@RunWith(Parameterized.class)
@Ignore
public class RecordCbcValidationTest {

	private static final int LOOPS = 500;
	private static final Map<Statistic, Long> allResults = new HashMap<Statistic, Long>();

	private static final byte[] FILLUP = Bytes.createBytes(new SecureRandom(), 256);

	int minVerifyPayloadLength = 1;
	int maxVerifyPayloadLength = 2;
	int minMacPayloadLength = 8;
	int maxMacPayloadLength = 256;

	byte[] payloadData;
	byte[] additionalData;
	SecureRandom secureRandom;
	DtlsBlockConnectionState state;
	Mac hmac;
	MessageDigest md;
	int blocks;
	int extra;
	boolean verbose = false;
	boolean throwOnFailure = false;
	boolean ceiling = false;

	/**
	 * Actual cipher suite.
	 */
	@Parameter
	public CipherSuite cipherSuite;

	/**
	 * @return List of cipher suites.
	 */
	@Parameters(name = "ciphersuite = {0}")
	public static Iterable<CipherSuite> cipherSuiteParams() {
		return Arrays.asList(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384);
	}

	@Before
	public void setUp() throws Exception {
		secureRandom = RandomManager.currentSecureRandom();
		assumeTrue("cipher suite " + cipherSuite.name() + " is not supported!", cipherSuite.isSupported());
		hmac = cipherSuite.getThreadLocalMac();
		md = cipherSuite.getThreadLocalMacMessageDigest();
		if (hmac.getMacLength() > 32) {
			minVerifyPayloadLength = 95;
			maxVerifyPayloadLength = 101;
		} else {
			minVerifyPayloadLength = 40;
			maxVerifyPayloadLength = 46;
		}
		int macKeyLength = cipherSuite.getMacKeyLength();
		SecretKey macKey = new SecretKeySpec(Bytes.createBytes(secureRandom, macKeyLength), "Mac");
		payloadData = Bytes.createBytes(secureRandom, Math.max(maxVerifyPayloadLength, maxMacPayloadLength));
		additionalData = Bytes.createBytes(secureRandom, 13);
		state = new DtlsBlockConnectionState(cipherSuite, CompressionMethod.NULL, macKey, macKey);
	}

	@AfterClass
	public static void statistic() {
		System.out.println("statistic:");
		statistic(allResults);
	}

	public static void statistic(Map<Statistic, Long> results) {
		final AtomicLong maxValue = new AtomicLong();
		final AtomicInteger maxKeyLen = new AtomicInteger();
		List<Entry<Statistic, Long>> entries = new ArrayList<Entry<Statistic, Long>>(results.entrySet());
		Collections.sort(entries, new Comparator<Entry<Statistic, Long>>() {

			private void adjustMaxKeyLen(int len) {
				if (maxKeyLen.get() < len) {
					maxKeyLen.set(len);
				}
			}

			private void adjustMaxValue(long value) {
				if (maxValue.get() < value) {
					maxValue.set(value);
				}
			}

			@Override
			public int compare(Entry<Statistic, Long> o1, Entry<Statistic, Long> o2) {
				adjustMaxKeyLen(o1.getKey().toString().length());
				adjustMaxKeyLen(o2.getKey().toString().length());
				adjustMaxValue(o1.getValue() / 1000);
				adjustMaxValue(o2.getValue() / 1000);
				return o1.getValue().compareTo(o2.getValue());
			}
		});
		int valueLen = Long.toString(maxValue.get()).length();
		for (Entry<Statistic, Long> entry : entries) {
			System.out.format(" * %-" + maxKeyLen.get() + "s: %" + valueLen + "d%n", entry.getKey().toString(),
					entry.getValue() / 1000);
		}
	}

	/**
	 * Application execute entry.
	 * 
	 * Takes up to a couple of hours.
	 * 
	 * @param args not used
	 */
	public static void main(String[] args) throws Exception {
		long time = System.nanoTime();
		RecordCbcValidationTest test = new RecordCbcValidationTest();
		test.cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256;
		test.setUp();
		test.testBenchmarkVerifyMacCompensation();
		test.testBenchmarkVerifyWithoutMacCompensation();
		statistic();
		time = System.nanoTime() - time;
		System.out.println("time: " + TimeUnit.NANOSECONDS.toMinutes(time) + " [min]");
	}

	@Test
	public void testVerify() throws GeneralSecurityException {
		for (int size = minVerifyPayloadLength; size < maxVerifyPayloadLength; ++size) {
			byte[] payload = Arrays.copyOf(payloadData, size);
			byte[] plaintext = prepareBlockWithMAC(payload, 64, state);
			byte[] verify = verifyMacCompensation(plaintext, state);
			assertArrayEquals(payload, verify);
			verify = verifyWithoutMacCompensation(plaintext, state);
			assertArrayEquals(payload, verify);
		}
	}

	@Test
	@Ignore
	public void testBenchmarkMac() throws GeneralSecurityException {
		hmac.init(state.getMacKey());
		byte[] mac = new byte[cipherSuite.getMacLength()];
		hmac.update(payloadData, 0, minMacPayloadLength);
		hmac.doFinal(mac, 0);
		int count = benchmarkMac(minMacPayloadLength, mac);
		for (int size = minMacPayloadLength; size < maxMacPayloadLength; ++size) {
			hmac.update(payloadData, 0, size);
			hmac.doFinal(mac, 0);
			count += benchmarkMac(size, mac);
		}
		System.out.println(": " + count);
	}

	private int benchmarkMac(int size, byte[] mac) throws GeneralSecurityException {
		byte[] mac2 = new byte[mac.length];
		int count = 0;
		long time = System.nanoTime();
		for (int loop = 0; loop < LOOPS * 100; ++loop) {
			try {
				hmac.update(payloadData, 0, size);
				hmac.doFinal(mac2, 0);
				if (!MessageDigest.isEqual(mac, mac2)) {
					++count;
				}
			} catch (Exception ex) {
				System.err.println(ex);
			}
		}
		time = System.nanoTime() - time;
		System.out.format("%s-%d-%d-%d: %d%n", hmac.getAlgorithm(), hmac.getMacLength(),
				state.getMacKey().getEncoded().length, size, time);
		return count;
	}

	@Test
	@Ignore
	public void testBenchmarkHash() throws GeneralSecurityException {
		byte[] mac = new byte[cipherSuite.getMacLength()];
		int count = 0;
		md.update(payloadData, 0, minMacPayloadLength);
		md.digest(mac, 0, mac.length);
		count += benchmarkHash(minMacPayloadLength, mac);
		for (int size = minMacPayloadLength; size < maxMacPayloadLength; ++size) {
			md.update(payloadData, 0, size);
			md.digest(mac, 0, mac.length);
			count += benchmarkHash(size, mac);
		}
		System.out.println(": " + count);
	}

	private int benchmarkHash(int size, byte[] mac) throws GeneralSecurityException {
		byte[] mac2 = new byte[mac.length];
		int count = 0;
		long time = System.nanoTime();
		for (int loop = 0; loop < LOOPS * 100; ++loop) {
			try {
				md.update(payloadData, 0, size);
				md.digest(mac2, 0, mac2.length);
				if (!MessageDigest.isEqual(mac, mac2)) {
					++count;
				}
			} catch (Exception ex) {
				System.err.println(ex);
			}
		}
		time = System.nanoTime() - time;
		System.out.format("%s-%d-%d: %d%n", md.getAlgorithm(), md.getDigestLength(), size, time);
		return count;
	}

	/**
	 * Test a verification , which uses the same numbers of compares and MAC
	 * blocks for all padding lengths.
	 */
	@Test
	public void testBenchmarkVerifyMacCompensation() throws GeneralSecurityException {
		Operate verify = new VerifyMacCompensation();
		ceiling = false;
		run("MAC compensation", verify, 0);
		run("MAC compensation", verify, state.getCipherSuite().getMacMessageBlockLength());
	}

	/**
	 * Test a verification , which uses the same numbers of compares and MAC
	 * blocks for all padding lengths. Use a ceiling function to calculate the
	 * numbers.
	 */
	@Test
	@Ignore
	public void testBenchmarkVerifyMacCompensationCeiling() throws GeneralSecurityException {
		Operate verify = new VerifyMacCompensation();
		ceiling = true;
		run("MAC compensation with ceiling", verify, 0);
		run("MAC compensation with ceiling", verify, state.getCipherSuite().getMacMessageBlockLength());
	}

	/**
	 * Test a verification, which doesn't care about the same numbers of
	 * compares and MAC blocks. Nor does it check the padding itself.
	 */
	@Test
	public void testBenchmarkVerifyWithoutMacCompensation() throws GeneralSecurityException {
		Operate verify = new VerifyWithoutMacCompensation();
		run("MAC none compen.", verify, 0);
		run("MAC none compen.", verify, state.getCipherSuite().getMacMessageBlockLength());
	}

	/**
	 * Run the test over all padding length byte values and repeat the test using
	 * always the same padding length byte value.
	 * 
	 * @param text description of the provided verification implementation
	 * @param verify operate calling the verification (part of record decrypt)
	 * @param additionalPadding use additional padding bytes
	 * @throws GeneralSecurityException if a security error occurred
	 */
	private void run(String text, Operate verify, int additionalPadding) throws GeneralSecurityException {
		text = hmac.getAlgorithm() + "-" + text;
		byte[] payload = Arrays.copyOf(payloadData, minVerifyPayloadLength);
		byte[] plaintext = prepareBlockWithMAC(payload, additionalPadding, state);
		int pad = plaintext[plaintext.length - 1] & 0xff;
		// Statistic statistic = run(plaintext, new Same(), verify);
		Statistic statistic = run(plaintext, "warmup 1", new PadIncrement(-1), verify);
		System.out.format("%s-%d-%d: %d%n", text, minVerifyPayloadLength, pad, statistic.avg / 1000);
		extra = 1;
		statistic = run(plaintext, "warmup 2", new PadIncrement(-1), verify);
		System.out.format("%s-%d-%d++: %d%n", text, minVerifyPayloadLength, pad, statistic.avg / 1000);
		extra = 0;
		statistic = run(plaintext, "warmup 3", new PadIncrement(-1), verify);
		System.out.format("%s-%d-%d: %d%n", text, minVerifyPayloadLength, pad, statistic.avg / 1000);
		for (int size = minVerifyPayloadLength; size < maxVerifyPayloadLength; ++size) {
			payload = Arrays.copyOf(payloadData, size);
			plaintext = prepareBlockWithMAC(payload, additionalPadding, state);
			pad = plaintext[plaintext.length - 1] & 0xff;
			String key = String.format("%s-%d-%02d-all*", text, size, pad);
			Statistic overall = new Statistic(key, 256);
			Statistic[] allStatistics = new Statistic[256];
			for (int p = 0; p < 256; ++p) {
				String k = String.format("%s-%d-%03d", text, size, p);
				Statistic sample = run(plaintext, k, new PadSet(p), verify);
				allStatistics[p] = sample;
				overall.add(sample.avg);
				if (p % 32 == 0) {
					System.out.println(sample);
				}
			}
			allResults.put(overall, overall.medianMaxMinDeviation());
			System.out.println(overall);
			plaintext = prepareBlockWithMAC(payload, additionalPadding, state);
			pad = plaintext[plaintext.length - 1] & 0xff;
			key = String.format("%s-%d-%02d-same", text, size, pad);
			overall = new Statistic(key, 256);
			allStatistics = new Statistic[256];
			for (int p = 0; p < 256; ++p) {
				String k = String.format("%s-%d-%03d", text, size, pad);
				Statistic sample = run(plaintext, k, new Same(), verify);
				allStatistics[p] = sample;
				overall.add(sample.avg);
				if (p % 32 == 0) {
					System.out.println(sample);
				}
			}
			allResults.put(overall, overall.medianMaxMinDeviation());
			System.out.println(overall);
		}
	}

	/**
	 * Run a single benchmark test. Run 256 loops, executing the pad operation
	 * together with {@link #LOOPS} verifications. Results in 256*{@link #LOOPS}
	 * verifications.
	 * 
	 * @param plaintext plaintext with MAC and padding
	 * @param description description of the verification.
	 * @param pad operate to manipulate the padding length byte
	 * @param verify operate to verification.
	 * @return statistic
	 * @throws GeneralSecurityException
	 */
	private Statistic run(byte[] plaintext, String description, Operate pad, Operate verify)
			throws GeneralSecurityException {
		// blocks = 0;
		plaintext = Arrays.copyOf(plaintext, plaintext.length);
		Statistic statistic = new Statistic(description, 256 * LOOPS);
		for (int index = 0; index < 256; ++index) {
			byte[] data = pad.operate(plaintext);
			long time = System.nanoTime();
			for (int loop = 0; loop < LOOPS; ++loop) {
				try {
					verify.operate(data);
				} catch (InvalidMacException ex) {
				} catch (Exception ex) {
					System.err.println(ex);
					ex.printStackTrace();
				}
			}
			time = System.nanoTime() - time;
			statistic.add(time);
		}
		return statistic;
	}

	/**
	 * Prepare plaintext with MAC and padding.
	 * 
	 * @param payload payload for plaintext.
	 * @param currentReadState current state for MAC.
	 * @return plaintext with MAC and padding
	 * @throws GeneralSecurityException if a crypto function fails
	 */
	private byte[] prepareBlockWithMAC(byte[] payload, int additionalPadding, DTLSConnectionState currentReadState)
			throws GeneralSecurityException {
		DatagramWriter plaintext = new DatagramWriter();
		plaintext.writeBytes(payload);

		// add MAC
		plaintext.writeBytes(CbcBlockCipher.getBlockCipherMac(state.getCipherSuite().getThreadLocalMac(),
				state.getMacKey(), additionalData, payload, payload.length));

		// determine padding length
		int ciphertextLength = payload.length + cipherSuite.getMacLength() + 1;
		int blocksize = cipherSuite.getRecordIvLength();
		int lastBlockBytes = ciphertextLength % blocksize;
		int paddingLength = lastBlockBytes > 0 ? blocksize - lastBlockBytes : 0;
		if (additionalPadding % blocksize != 0) {
			int blocks = (additionalPadding + blocksize - 1) / blocksize;
			additionalPadding = blocks * blocksize;
		}
		paddingLength += additionalPadding;
		// create padding
		byte[] padding = new byte[paddingLength + 1];
		Arrays.fill(padding, (byte) paddingLength);
		plaintext.writeBytes(padding);

		return plaintext.toByteArray();
	}

	/**
	 * Verify plaintext. Simple padding check and compensated MAC.
	 * 
	 * @param plaintext plaintext to check
	 * @param currentReadState state for MAC
	 * @return payload contained in plaintext
	 * @throws GeneralSecurityException if a crypto function fails or the MAC is
	 *             invalid
	 */
	private byte[] verifyMacCompensation(byte[] plaintext, DTLSConnectionState currentReadState)
			throws GeneralSecurityException {

		// consider extra block for estimate compression difference
		int additional = Math.max((currentReadState.getCipherSuite().getMacMessageBlockLength() * (1 + extra)), 256);
		int plaintextLength = plaintext.length;
		byte[] plaintextOversized = Arrays.copyOf(plaintext, plaintextLength + additional);
		System.arraycopy(FILLUP, 0, plaintextOversized, plaintextLength,
				currentReadState.getCipherSuite().getMacMessageBlockLength());

		/*
		 * See http://tools.ietf.org/html/rfc5246#section-6.2.3.2 for
		 * explanation
		 */
		int macLength = currentReadState.getCipherSuite().getMacLength();
		// last byte contains padding length
		int paddingLength = plaintextOversized[plaintextLength - 1] & 0xff;
		// -1 := padding length byte
		int fullLength = plaintextLength - macLength - 1;
		int leftLength = fullLength - paddingLength;
		int fragmentLength;
		if (leftLength < 0) {
			// padding length byte wrong
			fragmentLength = fullLength;
			paddingLength = 0;
		} else {
			fragmentLength = leftLength;
		}
		if (!CbcBlockCipher.checkPadding(paddingLength, plaintextOversized, fragmentLength + macLength)) {
			fragmentLength = fullLength;
			paddingLength = 0;
		}
		byte[] mac = CbcBlockCipher.getBlockCipherMac(state.getCipherSuite().getThreadLocalMac(), state.getMacKey(),
				additionalData, plaintextOversized, fragmentLength);
		md.reset();
		// estimate additional MAC calculations to decouple from padding
		// The MAC calculation is done in blocks, prepend the message length
		// ahead the message.
		int macMessageLengthBytes = currentReadState.getCipherSuite().getMacMessageLengthBytes();
		int macMessageBlockLength = currentReadState.getCipherSuite().getMacMessageBlockLength();
		// add all bytes passed to MAC
		int macBytes = macMessageLengthBytes + additionalData.length + fragmentLength;
		if (ceiling) {
			macBytes += (macMessageBlockLength - 1);
		}
		// MAC blocks for all bytes including padding
		int macBlocks1 = (macBytes + paddingLength) / macMessageBlockLength;
		// MAC blocks for all bytes without padding
		int macBlocks2 = macBytes / macMessageBlockLength;
		int extraBlocks = (macBlocks1 - macBlocks2) + extra;
		if (0 <= blocks && blocks < macBlocks1) {
			blocks = macBlocks1;
			System.out.format("%d of %d: %d-%d=>%d%n", fragmentLength, plaintextLength, macBlocks1, macBlocks2,
					extraBlocks);
		}
		// calculate extra compression to compensate timing differences caused by different padding
		// extra bytes, to ensure, that the compression is triggered
		md.update(plaintextOversized, fragmentLength, (extraBlocks * macMessageBlockLength) + 1);
		md.reset();
		byte[] macFromMessage = Arrays.copyOfRange(plaintextOversized, fragmentLength, fragmentLength + macLength);
		if (!MessageDigest.isEqual(macFromMessage, mac)) {
			if (throwOnFailure) {
				throw new InvalidMacException();
			}
			return null;
		}
		return Arrays.copyOf(plaintextOversized, fragmentLength);
	}

	/**
	 * The validation before the redesign of the CBC decrypt.
	 * 
	 * @param plaintext decrypted plaintext to verify the MAC
	 * @param currentReadState state to be used for MAC
	 * @return the plain payload on success
	 * @throws GeneralSecurityException If a crypto failure is detected
	 */
	private byte[] verifyWithoutMacCompensation(byte[] plaintext, DTLSConnectionState currentReadState)
			throws GeneralSecurityException {
		/*
		 * See http://tools.ietf.org/html/rfc5246#section-6.2.3.2 for
		 * explanation
		 */
		// last byte contains padding length
		int paddingLength = plaintext[plaintext.length - 1] & 0xff;
		int fragmentLength = plaintext.length - 1 // paddingLength byte
				- paddingLength - currentReadState.getCipherSuite().getMacLength();
		if (0 > fragmentLength) {
			throw new InvalidMacException();
		}
		DatagramReader reader = new DatagramReader(plaintext);
		byte[] content = reader.readBytes(fragmentLength);
		byte[] macFromMessage = reader.readBytes(currentReadState.getCipherSuite().getMacLength());
		byte[] mac = CbcBlockCipher.getBlockCipherMac(state.getCipherSuite().getThreadLocalMac(), state.getMacKey(),
				additionalData, content, fragmentLength);
		int macMessageBlockLength = currentReadState.getCipherSuite().getMacMessageBlockLength();
		// only to estimate the expected timing difference! No compensation is calculated!
		int extraBlocks = extra;
		while (extraBlocks > 0) {
			md.update(FILLUP, 0, macMessageBlockLength);
			--extraBlocks;
		}
		if (Arrays.equals(macFromMessage, mac)) {
			return content;
		} else {
			if (throwOnFailure) {
				throw new InvalidMacException(mac, macFromMessage);
			}
			return null;
		}
	}

	/**
	 * Statistic data.
	 */
	static public class Statistic {

		String description;
		/**
		 * Minimal value.
		 */
		long min;
		/**
		 * Maximal value.
		 */
		long max;
		/**
		 * Average value.
		 */
		long avg;
		/**
		 * Sum of values.
		 */
		long sum;
		/**
		 * Array with values
		 */
		long values[];
		/**
		 * Number of sampled values.
		 */
		int count;
		/**
		 * Index of minimum value.
		 */
		int minIndex;
		/**
		 * Index of maximum value.
		 */
		int maxIndex;
		/**
		 * Array with sorted values.
		 */
		long sorted[];

		/**
		 * Create Statistic.
		 * 
		 * @param length maximum number of values to be sampled.
		 */
		public Statistic(String description, int length) {
			this.description = description;
			values = new long[length];
		}

		/**
		 * Add value to samples.
		 * 
		 * @param value value to be added
		 */
		public void add(long value) {
			values[count] = value;
			if (count == 0) {
				min = value;
				max = value;
				sum = value;
				avg = value;
				count = 1;
				minIndex = 0;
				maxIndex = 0;
			} else {
				sum += value;
				if (sum < 0) {
					System.err.println("sum: " + sum);
					throw new Error("sum overflow!");
				}
				if (value < min) {
					min = value;
					minIndex = count;
				} else if (value > max) {
					max = value;
					maxIndex = count;
				}
				++count;
				avg = sum / count;
			}
		}

		/**
		 * Calculates the median and the deviation of min and may from that.
		 * 
		 * @return calculated value
		 */
		public long medianMaxMinDeviation() {
			long median = median();
			long diffMin = (min - median);
			long diffMax = (max - median);
			return (long) Math.sqrt((diffMax * diffMax) + (diffMin * diffMin));
		}

		/**
		 * Calculates median.
		 * 
		 * @return median
		 */
		public long median() {
			if (sorted == null || sorted.length != count) {
				sorted = Arrays.copyOf(values, count);
				Arrays.sort(sorted);
			}
			return sorted[count / 2];
		}

		/**
		 * Calculate variance. Average square of difference of values from
		 * average value.
		 * 
		 * @return variance
		 */
		public long variance() {
			long variance = 0;
			if (1 < count) {
				variance = squareDifference(avg) / count;
			}
			return variance;
		}

		/**
		 * Calculate the deviation.
		 *
		 * @return deviation.
		 */
		public long deviation() {
			long deviation = 0;
			if (1 < count) {
				deviation = squareDifference(avg) / (count - 1);
				deviation = (long) Math.sqrt(deviation);
			}
			return deviation;
		}

		private long squareDifference(long fixPoint) {
			long squareDiff = 0;
			if (1 < count) {
				for (int index = 0; index < count; ++index) {
					long diff = (values[index] - fixPoint);
					diff *= diff;
					if (diff < 0) {
						System.err.println("diff: " + diff);
						throw new Error("diff overflow!");
					}
					squareDiff += diff;
					if (squareDiff < 0) {
						System.err.println("square-diff-sum: " + squareDiff);
						throw new Error("square-diff-sum overflow!");
					}
				}
			}
			return squareDiff;
		}

		public String toString() {
			return String.format("%s: %4d[%03d] < %4d < %4d[%03d]", description, min / 1000, minIndex, avg / 1000, max / 1000,
					maxIndex);
		}
	}

	/**
	 * Generic operation on byte arrays.
	 */
	static interface Operate {

		byte[] operate(byte[] data) throws GeneralSecurityException;
	}

	/**
	 * Operation returning the same byte array as provided.
	 */
	static class Same implements Operate {

		@Override
		public byte[] operate(byte[] data) {
			return data;
		}

	}

	/**
	 * Operation replacing the last byte by an incremented value.
	 */
	static class PadIncrement implements Operate {

		int skip;
		int count;

		PadIncrement(int skip) {
			this.skip = skip;
		}

		@Override
		public byte[] operate(byte[] data) {
			++count;
			if (skip == (byte) count) {
				++count;
			}
			data[data.length - 1] = (byte) count;
			return data;
		}

	}

	/**
	 * Operation replacing the last byte by adding the provided value once.
	 */
	class PadAdd implements Operate {

		int add;

		PadAdd(int add) {
			this.add = add;
		}

		@Override
		public byte[] operate(byte[] data) {
			if (add != 0) {
				data[data.length - 1] += (byte) add;
				add = 0;
			}
			return data;
		}

	}

	/**
	 * Operation replacing the last byte by provided value.
	 */
	class PadSet implements Operate {

		int pad;

		PadSet(int pad) {
			this.pad = pad;
		}

		@Override
		public byte[] operate(byte[] data) {
			data[data.length - 1] = (byte) pad;
			if (data.length > 1 && pad == 1) {
				// apply the lucky13 trick
				data[data.length - 2] = (byte) pad;
			}
			return data;
		}

	}

	/**
	 * Operation executing the redesigned MAC verification.
	 */
	class VerifyMacCompensation implements Operate {

		@Override
		public byte[] operate(byte[] data) throws GeneralSecurityException {
			return verifyMacCompensation(data, state);
		}

	}

	/**
	 * Operation executing the old MAC verification.
	 */
	class VerifyWithoutMacCompensation implements Operate {

		@Override
		public byte[] operate(byte[] data) throws GeneralSecurityException {
			return verifyWithoutMacCompensation(data, state);
		}

	}
}
