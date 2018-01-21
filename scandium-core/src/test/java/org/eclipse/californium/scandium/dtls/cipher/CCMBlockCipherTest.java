package org.eclipse.californium.scandium.dtls.cipher;

import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.ProtocolVersion;
import org.eclipse.californium.scandium.util.ByteArrayUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@Category(Small.class)
@RunWith(Parameterized.class)
public class CCMBlockCipherTest {

	static final long SEQUENCE_NO = 5;
	static final int TYPE_APPL_DATA = 23;
	static final int EPOCH = 0;
	// byte representation of a 128 bit AES symmetric key
	static final byte[] aesKey = new byte[]{(byte) 0xC9, 0x0E, 0x6A, (byte) 0xA2, (byte) 0xEF, 0x60, 0x34, (byte) 0x96,
		(byte) 0x90, 0x54, (byte) 0xC4, (byte) 0x96, 0x65, (byte) 0xBA, 0x03, (byte) 0x9E};

	@Parameterized.Parameters
	public static List<Object[]> parameters() {
		// Trying different messages size to hit sharp corners in Coap-over-TCP
		// spec
		List<Object[]> parameters = new ArrayList<>();
		parameters.add(new Object[] { 0, 0, 7 });
		parameters.add(new Object[] { 5, 0, 7 });
		parameters.add(new Object[] { 13, 1, 7 });
		parameters.add(new Object[] { 15, 13, 8 });
		parameters.add(new Object[] { 16, 14, 8 });
		parameters.add(new Object[] { 17, 15, 12 });
		parameters.add(new Object[] { 31, 30, 13 });
		parameters.add(new Object[] { 32, 31, 12 });
		parameters.add(new Object[] { 33, 32, 12 });
		parameters.add(new Object[] { 65805, 256, 8 });
		parameters.add(new Object[] { 389805, 500, 8 });

		return parameters;
	}

	Random random;
	byte[] additionalData;
	byte[] nonce;
	
	byte[] payloadData;
	int payloadLength = 50;
	int aLength = 13;
	int nonceLength = 12;

	public CCMBlockCipherTest(int payloadLength, int aLength, int nonceLength) {
		this.payloadLength = payloadLength;
		this.aLength = aLength;
		this.nonceLength = nonceLength;
	}
	
	@Before
	public void setUp() throws Exception {
		// salt: 32bit client write init vector (can be any four bytes)
		byte[] client_iv = new byte[]{0x55, 0x23, 0x2F, (byte) 0xA3};
		ProtocolVersion protocolVer = new ProtocolVersion();
		payloadData = new byte[payloadLength];
		random = new Random(payloadLength);
		random.nextBytes(payloadData);
		
		// 64bit sequence number, consisting of 16bit epoch (0) + 48bit sequence number (5)
		byte[] seq_num = new byte[]{0x00, (byte) EPOCH, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) SEQUENCE_NO};
		
		// additional data based on sequence number, type (APPLICATION DATA) and protocol version
		additionalData = new byte[]{TYPE_APPL_DATA, (byte) protocolVer.getMajor(), (byte) protocolVer.getMinor(), 0, (byte) payloadLength};
		additionalData = ByteArrayUtils.concatenate(seq_num, additionalData);
		additionalData = adjustLength(additionalData, aLength);
		// "explicit" part of nonce, intentionally different from seq_num which MAY be used as the explicit nonce
		// but does not need to be used (at least that's my interpretation of the specs)
		byte[] explicitNonce = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
		// nonce used for encryption, "implicit" part + "explicit" part
		nonce = ByteArrayUtils.concatenate(client_iv, explicitNonce);
		nonce = adjustLength(nonce, nonceLength);
	}

	private byte[] adjustLength(byte[] data, int len) {
		if (data.length > len) {
			return ByteArrayUtils.truncate(data, len);
		} else if (data.length < len) {
			byte[] temp = new byte[len];
			random.nextBytes(temp);
			System.arraycopy(data, 0, temp, 0, data.length);
			return temp;
		}
		return data;
	}

	@Test
	public void testSlowSlowCryption() throws Exception {

		byte[] encryptedData = DeprecatesCCMBlockCipher.encrypt(aesKey, nonce, additionalData, payloadData, 8);
		byte[] decryptedData = DeprecatesCCMBlockCipher.decrypt(aesKey, nonce, additionalData, encryptedData, 8);
		assertTrue(Arrays.equals(decryptedData, payloadData));
	}

	@Test
	public void testFastFastCryption() throws Exception {

		byte[] encryptedData = CCMBlockCipher.encrypt(aesKey, nonce, additionalData, payloadData, 8);
		byte[] decryptedData = CCMBlockCipher.decrypt(aesKey, nonce, additionalData, encryptedData, 8);
		assertTrue(Arrays.equals(decryptedData, payloadData));
	}

	@Test
	public void testFastSlowCryption() throws Exception {

		byte[] encryptedData = CCMBlockCipher.encrypt(aesKey, nonce, additionalData, payloadData, 8);
		byte[] decryptedData = DeprecatesCCMBlockCipher.decrypt(aesKey, nonce, additionalData, encryptedData, 8);
		assertTrue(Arrays.equals(decryptedData, payloadData));
	}

	@Test
	public void testSlowFastCryption() throws Exception {

		byte[] encryptedData = DeprecatesCCMBlockCipher.encrypt(aesKey, nonce, additionalData, payloadData, 8);
		byte[] decryptedData = CCMBlockCipher.decrypt(aesKey, nonce, additionalData, encryptedData, 8);
		assertTrue(Arrays.equals(decryptedData, payloadData));
	}

	@Test(expected = InvalidMacException.class)
	public void testDifferentNonce() throws Exception {

		byte[] encryptedData = CCMBlockCipher.encrypt(aesKey, nonce, additionalData, payloadData, 8);
		byte[] nonce2 = Arrays.copyOf(nonce, nonce.length);
		nonce2[0] ^= 0x55;
		CCMBlockCipher.decrypt(aesKey, nonce2, additionalData, encryptedData, 8);
	}

	@Test(expected = InvalidMacException.class)
	public void testDifferentAdditionalData() throws Exception {

		byte[] encryptedData = CCMBlockCipher.encrypt(aesKey, nonce, additionalData, payloadData, 8);
		byte[] additionalData2 = Arrays.copyOf(additionalData, additionalData.length + 1);
		additionalData2[0] ^= 0x55;
		CCMBlockCipher.decrypt(aesKey, nonce, additionalData2, encryptedData, 8);
	}

	@Test(expected = InvalidMacException.class)
	public void testDifferentKey() throws Exception {

		byte[] encryptedData = CCMBlockCipher.encrypt(aesKey, nonce, additionalData, payloadData, 8);
		byte[] aesKey2 = Arrays.copyOf(aesKey, aesKey.length);
		aesKey2[0] ^= 0x55;
		CCMBlockCipher.decrypt(aesKey, nonce, aesKey2, encryptedData, 8);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testTooShortNonce() throws Exception {
		nonce = ByteArrayUtils.truncate(nonce, 6);
		CCMBlockCipher.encrypt(aesKey, nonce, additionalData, payloadData, 8);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testTooLongNonce() throws Exception {
		nonce = adjustLength(nonce, 14);
		CCMBlockCipher.encrypt(aesKey, nonce, additionalData, payloadData, 8);
	}

}
