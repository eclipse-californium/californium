/*******************************************************************************
 * Copyright (c) 2014, 2015 Bosch Software Innovations GmbH and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.util.DatagramWriter;

public class DtlsTestTools {

	public static final String TRUST_STORE_PASSWORD = "rootPass";
	public final static String KEY_STORE_PASSWORD = "endPass";
	public static final String KEY_STORE_LOCATION = "../certs/keyStore.jks";
	public static final String TRUST_STORE_LOCATION = "../certs/trustStore.jks";
	public static final long MAX_SEQUENCE_NO = 281474976710655L; // 2^48 - 1

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
		hmac.update(clientHello.getSessionId().getSessionId());
		hmac.update(CipherSuite.listToByteArray(clientHello.getCipherSuites()));
		hmac.update(CompressionMethod.listToByteArray(clientHello.getCompressionMethods()));
		return hmac.doFinal();
	}

	public static byte[] newClientCertificateTypesExtension(byte[] certificateTypes) {
		return newHelloExtension(19, certificateTypes);
	}

	public static byte[] newServerCertificateTypesExtension(byte[] certificateTypes) {
		return newHelloExtension(20, certificateTypes);
	}

	public static byte[] newHelloExtension(int typeCode, byte[] extensionBytes) {
		DatagramWriter writer = new DatagramWriter();
		writer.write(typeCode, 16);
		writer.write(extensionBytes.length, 16);
		writer.writeBytes(extensionBytes);
		return writer.toByteArray();
	}
	
	public static KeyStore loadKeyStore(String keyStoreLocation, String keyStorePassword)
			throws IOException, GeneralSecurityException {
		char[] passwd = keyStorePassword.toCharArray();
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(new FileInputStream(keyStoreLocation), passwd);
		return keyStore;
	}
	
	public static Key getKeyFromStore(String keyStoreLocation, String keyStorePassword, String keyAlias)
			throws IOException, GeneralSecurityException {
		KeyStore keyStore = loadKeyStore(keyStoreLocation, keyStorePassword);
		return keyStore.getKey(keyAlias, keyStorePassword.toCharArray());
	}

	public static Certificate[] getCertificateChainFromStore(String keyStoreLocation, String keyStorePassword, String alias)
			throws IOException, GeneralSecurityException {
		KeyStore keyStore = loadKeyStore(keyStoreLocation, keyStorePassword);
		return keyStore.getCertificateChain(alias);
	}

	public static PrivateKey getPrivateKey() throws IOException, GeneralSecurityException {
		return (PrivateKey) DtlsTestTools.getKeyFromStore(DtlsTestTools.KEY_STORE_LOCATION,
				DtlsTestTools.KEY_STORE_PASSWORD, "server");
	}

	public static PublicKey getPublicKey() throws IOException, GeneralSecurityException {
		Certificate[] certChain = DtlsTestTools.getCertificateChainFromStore(DtlsTestTools.KEY_STORE_LOCATION,
				DtlsTestTools.KEY_STORE_PASSWORD, "server");
		return certChain[0].getPublicKey();
	}
	
	public static Certificate[] getTrustedCertificates() throws IOException, GeneralSecurityException {
		KeyStore trustStore = loadKeyStore(TRUST_STORE_LOCATION, TRUST_STORE_PASSWORD);
		// You can load multiple certificates if needed
		Certificate[] trustedCertificates = new Certificate[1];
		trustedCertificates[0] = trustStore.getCertificate("root");
		return trustedCertificates;
	}
}