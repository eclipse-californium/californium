/*******************************************************************************
 * Copyright (c) 2015, 2016 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add method for retrieving
 *                                                    trust anchor
 *    Kai Hudalla (Bosch Software Innovations GmbH) - explicitly support retrieving client & server keys
 *                                                    and certificate chains 
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.junit.Assert.assertFalse;

import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.TestCertificatesTools;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.util.ServerName;

public final class DtlsTestTools extends TestCertificatesTools {

	public static final long MAX_SEQUENCE_NO = 281474976710655L; // 2^48 - 1

	private DtlsTestTools() {
	}

	public static Record getRecordForMessage(int epoch, int seqNo, DTLSMessage msg, InetSocketAddress peer) {
		byte[] dtlsRecord = newDTLSRecord(msg.getContentType().getCode(), epoch,
				seqNo, msg.toByteArray());
		List<Record> list = Record.fromByteArray(dtlsRecord, peer, null, ClockUtil.nanoRealtime());
		assertFalse("Should be able to deserialize DTLS Record from byte array", list.isEmpty());
		return list.get(0);
	}

	public static final byte[] newDTLSRecord(int typeCode, int epoch, long sequenceNo, byte[] fragment) {

		ProtocolVersion protocolVer = new ProtocolVersion();
		// the record header contains a type code, version, epoch, sequenceNo, length
		DatagramWriter writer = new DatagramWriter();
		writer.write(typeCode, 8);
		writer.write(protocolVer.getMajor(), 8);
		writer.write(protocolVer.getMinor(), 8);
		writer.write(epoch, 16);
		writer.writeLong(sequenceNo, 48);
		writer.write(fragment.length, 16);
		writer.writeBytes(fragment);
		return writer.toByteArray();
	}

	public static final byte[] generateCookie(InetSocketAddress endpointAddress, ClientHello clientHello)
			throws GeneralSecurityException {
		
		// Cookie = HMAC(Secret, Client-IP, Client-Parameters)
		Mac hmac = Mac.getInstance("HmacSHA256");
		hmac.init(new SecretKeySpec("generate cookie".getBytes(), "Mac"));
		// Client-IP
		hmac.update(endpointAddress.toString().getBytes());

		// Client-Parameters
		hmac.update((byte) clientHello.getClientVersion().getMajor());
		hmac.update((byte) clientHello.getClientVersion().getMinor());
		hmac.update(clientHello.getRandom().getBytes());
		hmac.update(clientHello.getSessionId().getBytes());
		hmac.update(CipherSuite.listToByteArray(clientHello.getCipherSuites()));
		hmac.update(CompressionMethod.listToByteArray(clientHello.getCompressionMethods()));
		return hmac.doFinal();
	}

	public static byte[] newClientCertificateTypesExtension(int... types) {
		DatagramWriter writer = new DatagramWriter();
		writer.write(types.length, 8);
		for (int type : types) {
			writer.write(type, 8);
		}
		return newHelloExtension(19, writer.toByteArray());
	}

	public static byte[] newServerCertificateTypesExtension(int... types) {
		DatagramWriter writer = new DatagramWriter();
		writer.write(types.length, 8);
		for (int type : types) {
			writer.write(type, 8);
		}
		return newHelloExtension(20, writer.toByteArray());
	}

	public static byte[] newSupportedEllipticCurvesExtension(int... curveIds) {
		DatagramWriter writer = new DatagramWriter();
		writer.write(curveIds.length * 2, 16);
		for (int type : curveIds) {
			writer.write(type, 16);
		}
		return newHelloExtension(10, writer.toByteArray());
	}

	public static byte[] newMaxFragmentLengthExtension(int lengthCode) {
		return newHelloExtension(1, new byte[]{(byte) lengthCode});
	}

	public static byte[] newServerNameExtension(final String hostName) {

		byte[] name = hostName.getBytes(ServerName.CHARSET);
		DatagramWriter writer = new DatagramWriter();
		writer.write(name.length + 3, 16); //server_name_list_length
		writer.writeByte((byte) 0x00);
		writer.write(name.length, 16);
		writer.writeBytes(name);
		return newHelloExtension(0, writer.toByteArray());
	}

	public static byte[] newHelloExtension(int typeCode, byte[] extensionBytes) {
		DatagramWriter writer = new DatagramWriter();
		writer.write(typeCode, 16);
		writer.write(extensionBytes.length, 16);
		writer.writeBytes(extensionBytes);
		return writer.toByteArray();
	}
}
