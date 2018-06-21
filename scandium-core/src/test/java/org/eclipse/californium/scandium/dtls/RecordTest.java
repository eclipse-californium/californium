/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add test cases for verifying sequence number handling
 *    Achim Kraus (Bosch Software Innovations GmbH) - Replace getLocalHost() by
 *                                                    getLoopbackAddress()
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.ProtocolVersion;
import org.eclipse.californium.scandium.dtls.cipher.CCMBlockCipher;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.util.ByteArrayUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class RecordTest {

	static final long SEQUENCE_NO = 5;
	static final int TYPE_APPL_DATA = 23;
	static final int EPOCH = 0;
	// byte representation of a 128 bit AES symmetric key
	static final byte[] aesKey = new byte[]{(byte) 0xC9, 0x0E, 0x6A, (byte) 0xA2, (byte) 0xEF, 0x60, 0x34, (byte) 0x96,
		(byte) 0x90, 0x54, (byte) 0xC4, (byte) 0x96, 0x65, (byte) 0xBA, 0x03, (byte) 0x9E};
	SecretKey key;
	
	DTLSSession session;
	byte[] payloadData;
	int payloadLength = 50;
	// salt: 32bit client write init vector (can be any four bytes)
	byte[] client_iv = new byte[]{0x55, 0x23, 0x2F, (byte) 0xA3};
	ProtocolVersion protocolVer;
	
	@Before
	public void setUp() throws Exception {
		
		protocolVer = new ProtocolVersion();
		key = new SecretKeySpec(aesKey, "AES");
		payloadData = new byte[payloadLength];
		for ( int i = 0; i < payloadLength; i++) {
			payloadData[i] = 0x34;
		}
		session = new DTLSSession(new InetSocketAddress(InetAddress.getLoopbackAddress(), 7000), true);
		DTLSConnectionState readState = new DTLSConnectionState(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
				CompressionMethod.NULL, key, new IvParameterSpec(client_iv), null);
		session.setReadState(readState);
	}

	@Test
	public void testConstructorEnforcesMaxSequenceNo() throws GeneralSecurityException {
		new Record(ContentType.HANDSHAKE, 0, DtlsTestTools.MAX_SEQUENCE_NO, new HelloRequest(session.getPeer()), session);
		try {
			new Record(ContentType.HANDSHAKE, 0, DtlsTestTools.MAX_SEQUENCE_NO + 1, new HelloRequest(session.getPeer()), session);
			Assert.fail("Record constructor should have rejected sequence no > 2^48 - 1");
		} catch (IllegalArgumentException e) {
			// all is well
		}

		try {
			new Record(ContentType.HANDSHAKE, 0, DtlsTestTools.MAX_SEQUENCE_NO + 1, new HelloRequest(session.getPeer()), session.getPeer());
			Assert.fail("Record constructor should have rejected sequence no > 2^48 - 1");
		} catch (IllegalArgumentException e) {
			// all is well
		}
	}
	
	@Test
	public void testSetSequenceNumberEnforcesMaxSequenceNo() throws GeneralSecurityException {
		Record record = new Record(ContentType.HANDSHAKE, 0, 0, new HelloRequest(session.getPeer()), session.getPeer());
		record.setSequenceNumber(DtlsTestTools.MAX_SEQUENCE_NO);
		try {
			record.setSequenceNumber(DtlsTestTools.MAX_SEQUENCE_NO + 1);
			Assert.fail("Method should have rejected sequence no > 2^48 - 1");
		} catch (IllegalArgumentException e) {
			// all is well
		}
	}
	
	@Test
	public void testFromByteArrayRejectsIllformattedRecord() {
		byte[] illformattedRecord = new byte[]{TYPE_APPL_DATA};
		List<Record> recordList = Record.fromByteArray(illformattedRecord, session.getPeer());
		assertTrue("fromByteArray() should have detected malformed record", recordList.isEmpty());
	}
	
	@Test
	public void testFromByteArrayAcceptsKnownTypeCode() throws GeneralSecurityException {
		
		byte[] application_record = DtlsTestTools.newDTLSRecord(TYPE_APPL_DATA, EPOCH, SEQUENCE_NO, newGenericAEADCipherFragment());
		List<Record> recordList = Record.fromByteArray(application_record, session.getPeer());
		assertEquals(recordList.size(), 1);
		Record record = recordList.get(0);
		assertEquals(ContentType.APPLICATION_DATA, record.getType());
		assertEquals(EPOCH, record.getEpoch());
		assertEquals(SEQUENCE_NO, record.getSequenceNumber());
		assertEquals(protocolVer.getMajor(), record.getVersion().getMajor());
		assertEquals(protocolVer.getMinor(), record.getVersion().getMinor());
	}
	
	@Test
	public void testFromByteArrayRejectsUnknownTypeCode() throws GeneralSecurityException {
		
		byte[] application_record = DtlsTestTools.newDTLSRecord(TYPE_APPL_DATA, EPOCH, SEQUENCE_NO, newGenericAEADCipherFragment());
		byte[] unsupported_dtls_record = DtlsTestTools.newDTLSRecord(55, EPOCH, SEQUENCE_NO, newGenericAEADCipherFragment());
		
		List<Record> recordList = Record.fromByteArray(ByteArrayUtils.concatenate(unsupported_dtls_record, application_record), session.getPeer());
		Assert.assertTrue(recordList.size() == 1);
		Assert.assertEquals(ContentType.APPLICATION_DATA, recordList.get(0).getType());
	}
	
	/**
	 * Checks whether the {@link Record#decryptAEAD(byte[])} method uses the <em>explicit</em>
	 * nonce part included in the <i>GenericAEADCipher</i> struct instead of deriving the
	 * explicit nonce part frmo the epoch and sequence number contained in the <i>DTLSCiphertext</i>
	 * struct.
	 * 
	 * @throws Exception if decryption fails
	 */
	@Test
	public void testDecryptAEADUsesExplicitNonceFromGenericAEADCipherStruct() throws Exception {
		
		byte[] fragment = newGenericAEADCipherFragment();
		Record record = new Record(ContentType.APPLICATION_DATA, protocolVer, EPOCH, SEQUENCE_NO, fragment, session.getPeer());
		record.setSession(session);
		
		byte[] decryptedData = record.decryptAEAD(fragment, session.getReadState());
		assertTrue(Arrays.equals(decryptedData, payloadData));
	}
	
	byte[] newGenericAEADCipherFragment() throws GeneralSecurityException {
		// 64bit sequence number, consisting of 16bit epoch (0) + 48bit sequence number (5)
		byte[] seq_num = new byte[]{0x00, (byte) EPOCH, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) SEQUENCE_NO};
		
		// additional data based on sequence number, type (APPLICATION DATA) and protocol version
		byte[] additionalData = new byte[]{TYPE_APPL_DATA, (byte) protocolVer.getMajor(), (byte) protocolVer.getMinor(), 0, (byte) payloadLength};
		additionalData = ByteArrayUtils.concatenate(seq_num, additionalData);

		// "explicit" part of nonce, intentionally different from seq_num which MAY be used as the explicit nonce
		// but does not need to be used (at least that's my interpretation of the specs)
		byte[] explicitNonce = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
		// nonce used for encryption, "implicit" part + "explicit" part
		byte[] nonce = ByteArrayUtils.concatenate(client_iv, explicitNonce);
		
		byte[] encryptedData = CCMBlockCipher.encrypt(key.getEncoded(), nonce, additionalData, payloadData, 8);
		
		// prepend the "explicit" part of nonce to the encrypted data to form the GenericAEADCipher struct
		return ByteArrayUtils.concatenate(explicitNonce, encryptedData);
	}
}
