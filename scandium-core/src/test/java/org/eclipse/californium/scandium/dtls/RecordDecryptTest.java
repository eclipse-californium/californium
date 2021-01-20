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
import static org.junit.Assert.assertFalse;
import static org.junit.Assume.assumeTrue;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.RandomManager;
import org.eclipse.californium.scandium.util.SecretIvParameterSpec;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/**
 * This test validates the robustness of {@link Record#decryptFragment}.
 */
@RunWith(Parameterized.class)
@Category(Small.class)
public class RecordDecryptTest {

	static final int TYPE_APPL_DATA = 23;
	static final int EPOCH = 1;
	static final boolean DUMP = false;

	DTLSContext context;
	byte[] payloadData;
	int payloadLength = 128;

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
		return Arrays.asList(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
				CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
				CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
				CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
				CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384);
	}

	@Before
	public void setUp() throws Exception {
		SecureRandom secureRandom = RandomManager.currentSecureRandom();
		assumeTrue("cipher suite " + cipherSuite.name() + " is not supported!", cipherSuite.isSupported());
		int encKeyLength = cipherSuite.getEncKeyLength();
		int macKeyLength = cipherSuite.getMacKeyLength();
		int ivLength = cipherSuite.getFixedIvLength();
		SecretKey encKey = new SecretKeySpec(Bytes.createBytes(secureRandom, encKeyLength), "AES");
		SecretKey macKey = macKeyLength == 0 ? null
				: new SecretKeySpec(Bytes.createBytes(secureRandom, macKeyLength), "AES");
		SecretIvParameterSpec iv = ivLength > 0 ? new SecretIvParameterSpec(Bytes.createBytes(secureRandom, ivLength)) : null;
		payloadData = Bytes.createBytes(secureRandom, payloadLength);

		DTLSSession session = new DTLSSession();
		session.setCipherSuite(cipherSuite);
		session.setCompressionMethod(CompressionMethod.NULL);
		context = new DTLSContext(session, 0);
		context.createReadState(encKey, iv, macKey);
		context.createWriteState(encKey, iv, macKey);
	}

	/**
	 * Test, if payload of different sizes could be encrypted and decrypted.
	 * 
	 * @throws GeneralSecurityException if a crypto error occurs
	 * @throws HandshakeException if a handshake error occurs
	 */
	@Test
	public void testEncrypDecrypt() throws GeneralSecurityException, HandshakeException {
		for (int size = 1; size < payloadLength; ++size) {
			byte[] payload = Arrays.copyOf(payloadData, size);
			testEncryptDecrypt(payload);
		}
	}

	/**
	 * Create application record with provided data. Encrypt, decrypt and
	 * compare the payload/fragment.
	 * 
	 * @param payload payload of fragment
	 * @throws GeneralSecurityException if a crypto error occurs
	 * @throws HandshakeException if a handshake error occurs
	 */
	private void testEncryptDecrypt(byte[] payload) throws GeneralSecurityException, HandshakeException {
		Record record = new Record(ContentType.APPLICATION_DATA, EPOCH, new ApplicationMessage(payload),
				context, true, 0);
		byte[] raw = record.toByteArray();
		List<Record> list = DtlsTestTools.fromByteArray(raw, null, ClockUtil.nanoRealtime());
		assertFalse("failed to decode raw message", list.isEmpty());
		for (Record recv : list) {
			recv.decodeFragment(context.getReadState());
			DTLSMessage message = recv.getFragment();
			assertArrayEquals("decrypted payload differs", payload, message.toByteArray());
		}
	}

	/**
	 * Test manipulating the raw record length (without adjust the header
	 * length)
	 */
	@Test
	public void testEncrypDecryptRecordLengthFailure() {
		testEncryptDecryptRecordFailure(new LengthJuggler());
	}

	/**
	 * Test manipulating the encrypted fragment record length (with adjust the
	 * header length)
	 */
	@Test
	public void testEncrypDecryptFragmentLengthFailure() {
		testEncryptDecryptFragmentFailure(new LengthJuggler());
	}

	/**
	 * Test manipulating the encrypted fragment record length (with adjust the
	 * header length)
	 */
	@Test
	public void testEncrypDecryptFragmentAllLengthFailure() {
		for (int size = 15; size < 32 + 17; ++size) {
			byte[] payload = Arrays.copyOf(payloadData, size);
			for (int delta = -size; delta < size + 10; ++delta) {
				try {
					testEncryptDecryptFragmentFailure(payload, new FixedLengthJuggler(delta));
				} catch (GeneralSecurityException | HandshakeException ex) {
					// such exception are OK, RuntimeException are failures
				}
			}
		}
	}

	/**
	 * Test manipulating the raw record bytes (including the header)
	 */
	@Test
	public void testEncrypDecryptRecordBytesFailure() {
		testEncryptDecryptRecordFailure(new BytesJuggler(5));
	}

	/**
	 * Test manipulating the encrypted fragment record bytes (excluding the
	 * header)
	 */
	@Test
	public void testEncrypDecryptFragmentBytesFailure() {
		testEncryptDecryptFragmentFailure(new BytesJuggler(5));
	}

	/**
	 * Test manipulating the raw record bytes and length (including the header,
	 * without adjust the header length)
	 */
	@Test
	public void testEncrypDecryptRecordCombiFailure() {
		testEncryptDecryptRecordFailure(new CombiJuggler(15));
	}

	/**
	 * Test manipulating the encrypted fragment record bytes and length
	 * (excluding the header, with adjust the header length)
	 */
	@Test
	public void testEncrypDecryptFragmentCombiFailure() {
		testEncryptDecryptFragmentFailure(new CombiJuggler(15));
	}

	/**
	 * Apply manipulation to the record bytes with different payload sizes.
	 * 
	 * @param juggler juggler to be used for the test.
	 */
	private void testEncryptDecryptRecordFailure(Juggler juggler) {
		for (int size = 1; size < payloadLength; ++size) {
			byte[] payload = Arrays.copyOf(payloadData, size);
			try {
				testEncryptDecryptRecordFailure(payload, juggler);
			} catch (GeneralSecurityException | HandshakeException ex) {
				// such exception are OK, RuntimeException are failures
			}
		}
	}

	/**
	 * Apply manipulation to the record bytes.
	 * 
	 * @param payload payload for application record.
	 * @param juggler juggler to be used for the test.
	 * @throws GeneralSecurityException if a crypto error occurs. No failure,
	 *             maybe caused by the manipulations
	 * @throws HandshakeException if a handshake error occurs. No failure, maybe
	 *             caused by the manipulations
	 */
	private void testEncryptDecryptRecordFailure(byte[] payload, Juggler juggler)
			throws GeneralSecurityException, HandshakeException {
		Record record = new Record(ContentType.APPLICATION_DATA, EPOCH, new ApplicationMessage(payload),
				context, true, 0);
		byte[] raw = record.toByteArray();
		byte[] jraw = juggler.juggle(raw);
		dumpDiff(raw, jraw);
		List<Record> list = DtlsTestTools.fromByteArray(jraw, null, ClockUtil.nanoRealtime());
		for (Record recv : list) {
			if (recv.getEpoch() != EPOCH) {
				// skip
				continue;
			}
			recv.decodeFragment(context.getReadState());
			recv.getFragment();
		}
	}

	/**
	 * Apply manipulation to the encrypted fragment record bytes with different
	 * payload sizes.
	 * 
	 * @param juggler juggler to be used for the test.
	 */
	private void testEncryptDecryptFragmentFailure(Juggler juggler) {
		for (int size = 1; size < payloadLength; ++size) {
			byte[] payload = Arrays.copyOf(payloadData, size);
			try {
				testEncryptDecryptFragmentFailure(payload, juggler);
			} catch (GeneralSecurityException | HandshakeException ex) {
				// such exception are OK, RuntimeException are failures
			}
		}
	}

	/**
	 * Apply manipulation to the encrypted fragment record bytes.
	 * 
	 * @param payload payload for application record.
	 * @param juggler juggler to be used for the test.
	 * @throws GeneralSecurityException if a crypto error occurs. No failure,
	 *             maybe caused by the manipulations
	 * @throws HandshakeException if a handshake error occurs. No failure, maybe
	 *             caused by the manipulations
	 */
	private void testEncryptDecryptFragmentFailure(byte[] payload, Juggler juggler)
			throws GeneralSecurityException, HandshakeException {
		Record record = new Record(ContentType.APPLICATION_DATA, EPOCH, new ApplicationMessage(payload),
				context, true, 0);
		byte[] fragment = record.getFragmentBytes();
		byte[] jfragment = juggler.juggle(fragment);
		dumpDiff(fragment, jfragment);
		byte[] raw = toByteArray(record, jfragment);
		List<Record> list = DtlsTestTools.fromByteArray(raw, null, ClockUtil.nanoRealtime());
		for (Record recv : list) {
			recv.decodeFragment(context.getReadState());
			recv.getFragment();
		}
	}

	/**
	 * Write record with manipulated encrypted fragment record bytes
	 * 
	 * @param record record
	 * @param fragment manipulated encrypted fragment record bytes
	 * @return manipulated record bytes
	 */
	private byte[] toByteArray(Record record, byte[] fragment) {
		DatagramWriter writer = new DatagramWriter();
		if (record.useConnectionId()) {
			writer.write(ContentType.TLS12_CID.getCode(), Record.CONTENT_TYPE_BITS);
		} else {
			writer.write(record.getType().getCode(), Record.CONTENT_TYPE_BITS);
		}

		writer.write(record.getVersion().getMajor(), Record.VERSION_BITS);
		writer.write(record.getVersion().getMinor(), Record.VERSION_BITS);

		writer.write(record.getEpoch(), Record.EPOCH_BITS);
		writer.writeLong(record.getSequenceNumber(), Record.SEQUENCE_NUMBER_BITS);
		if (record.useConnectionId()) {
			writer.writeBytes(record.getConnectionId().getBytes());
		}
		writer.write(fragment.length, Record.LENGTH_BITS);
		writer.writeBytes(fragment);

		return writer.toByteArray();
	}

	public static void dumpDiff(byte[] data1, byte[] data2) {
		if (DUMP) {
			if (!Arrays.equals(data1, data2)) {
				StringBuilder line = new StringBuilder();
				int end = data1.length;
				if (end != data2.length) {
					end = Math.min(data1.length, data2.length);
					line.append(String.format("[%d!=%d]", data1.length, data2.length));
				}
				for (int index = 0; index < end; ++index) {
					if (data1[index] != data2[index]) {
						line.append(String.format("[%d]%02x!=%02x", index, data1[index] & 0xff, data2[index] & 0xff));
					}
				}
				System.out.println(line);
			}
		}
	}

	/**
	 * Bytes manipulator.
	 */
	interface Juggler {

		/**
		 * Manipulate provided bytes.
		 * 
		 * @param data provided bytes. MUST not be changed
		 * @return manipulated bytes
		 */
		byte[] juggle(byte[] data);
	}

	/**
	 * Manipulate the length.
	 */
	static class FixedLengthJuggler implements Juggler {

		final int delta;

		private FixedLengthJuggler(int delta) {
			this.delta = delta;
		}

		@Override
		public byte[] juggle(byte[] data) {
			int length = data.length + delta;
			if (length < 0) {
				length = 0;
			}
			return Arrays.copyOf(data, length);
		}
	}

	/**
	 * Manipulate the length.
	 */
	static class LengthJuggler implements Juggler {

		private SecureRandom secureRandom = RandomManager.currentSecureRandom();

		@Override
		public byte[] juggle(byte[] data) {
			return Arrays.copyOf(data, secureRandom.nextInt(data.length + 32));
		}
	}

	/**
	 * Manipulate the bytes content.
	 */
	static class BytesJuggler implements Juggler {

		private SecureRandom secureRandom = RandomManager.currentSecureRandom();
		private int count;

		BytesJuggler(int count) {
			this.count = count;
		}

		@Override
		public byte[] juggle(byte[] data) {
			if (data.length > 0) {
				data = Arrays.copyOf(data, data.length);
				for (int mods = 0; mods < count; ++mods) {
					int index = secureRandom.nextInt(data.length);
					data[index] = (byte) secureRandom.nextInt(256);
				}
			}
			return data;
		}
	}

	/**
	 * Manipulate the length and bytes content.
	 */
	static class CombiJuggler implements Juggler {

		private LengthJuggler length = new LengthJuggler();
		private BytesJuggler bytes;

		CombiJuggler(int count) {
			bytes = new BytesJuggler(count);
		}

		@Override
		public byte[] juggle(byte[] data) {
			data = length.juggle(data);
			data = bytes.juggle(data);
			return data;
		}
	}

}
