/*******************************************************************************
 * Copyright (c) 2015, 2016 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - inital creation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add method for retrieving
 *                                                    trust anchor
 *    Kai Hudalla (Bosch Software Innovations GmbH) - explicitly support retrieving client & server keys
 *                                                    and certificate chains 
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Enumeration;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

public final class DtlsTestTools {

	public static final String TRUST_STORE_PASSWORD = "rootPass";
	public final static String KEY_STORE_PASSWORD = "endPass";
	public static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	public static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";
	public static final String SERVER_NAME = "server";
	public static final String CLIENT_NAME = "client";
	public static final long MAX_SEQUENCE_NO = 281474976710655L; // 2^48 - 1
	private static KeyStore keyStore;
	private static KeyStore trustStore;
	private static Certificate[] trustedCertificates = new Certificate[1];
	private static Certificate[] serverCertificateChain;
	private static Certificate[] clientCertificateChain;

	static {
		try {
			// load key stores once only
			keyStore = loadKeyStore(KEY_STORE_LOCATION, KEY_STORE_PASSWORD);
			trustStore = loadKeyStore(TRUST_STORE_LOCATION, TRUST_STORE_PASSWORD);
			trustedCertificates = new Certificate[trustStore.size()];
			int j = 0;
			for (Enumeration<String> e = trustStore.aliases(); e.hasMoreElements(); ) {
				trustedCertificates[j++] = trustStore.getCertificate(e.nextElement());
			}
			serverCertificateChain = keyStore.getCertificateChain(SERVER_NAME);
			clientCertificateChain = keyStore.getCertificateChain(CLIENT_NAME);
		} catch (IOException | GeneralSecurityException e) {
			// nothing we can do
		}
	}

	private DtlsTestTools() {
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
		hmac.update(clientHello.getRandom().getRandomBytes());
		hmac.update(clientHello.getSessionId().getId());
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

		byte[] name = hostName.getBytes(StandardCharsets.US_ASCII);
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

	private static KeyStore loadKeyStore(String keyStoreLocation, String keyStorePassword)
			throws IOException, GeneralSecurityException {
		char[] passwd = keyStorePassword.toCharArray();
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(DtlsTestTools.class.getClassLoader().getResourceAsStream(keyStoreLocation), passwd);
		return keyStore;
	}

	public static Certificate[] getServerCertificateChain()	throws IOException, GeneralSecurityException {
		return Arrays.copyOf(serverCertificateChain, serverCertificateChain.length);
	}

	public static Certificate[] getClientCertificateChain()	throws IOException, GeneralSecurityException {
		return Arrays.copyOf(clientCertificateChain, clientCertificateChain.length);
	}

	/**
	 * Gets the server's private key from the example key store.
	 * 
	 * @return the key
	 * @throws IOException if the key store cannot be read
	 * @throws GeneralSecurityException if the key cannot be found
	 */
	public static PrivateKey getPrivateKey() throws IOException, GeneralSecurityException {
		return (PrivateKey) keyStore.getKey(SERVER_NAME, KEY_STORE_PASSWORD.toCharArray());
	}

	/**
	 * Gets the client's private key from the example key store.
	 * 
	 * @return the key
	 * @throws IOException if the key store cannot be read
	 * @throws GeneralSecurityException if the key cannot be found
	 */
	public static PrivateKey getClientPrivateKey() throws IOException, GeneralSecurityException {
		return (PrivateKey) keyStore.getKey(CLIENT_NAME, KEY_STORE_PASSWORD.toCharArray());
	}

	/**
	 * Gets the server's public key from the example key store.
	 * 
	 * @return the key
	 * @throws IOException if the key store cannot be read
	 * @throws GeneralSecurityException if the key cannot be found
	 */
	public static PublicKey getPublicKey() throws IOException, GeneralSecurityException {
		Certificate[] certChain = keyStore.getCertificateChain(SERVER_NAME);
		return certChain[0].getPublicKey();
	}

	/**
	 * Gets the client's public key from the example key store.
	 * 
	 * @return the key
	 * @throws IOException if the key store cannot be read
	 * @throws GeneralSecurityException if the key cannot be found
	 */
	public static PublicKey getClientPublicKey() throws IOException, GeneralSecurityException {
		Certificate[] certChain = keyStore.getCertificateChain(CLIENT_NAME);
		return certChain[0].getPublicKey();
	}

	public static Certificate[] getTrustedCertificates() throws IOException, GeneralSecurityException {
		return trustedCertificates;
	}
}
