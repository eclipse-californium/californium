/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla, Bosch Software Innovations GmbH
 *    Kai Hudalla (Bosch Software Innovations GmbH) - adapt to HelloExtensions changes
 *    Achim Kraus (Bosch Software Innovations GmbH) - Replace getLocalHost() by
 *                                                    getLoopbackAddress()
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.List;

import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.CertificateTypeExtension.CertificateType;
import org.eclipse.californium.scandium.dtls.HelloExtension.ExtensionType;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class HelloExtensionsTest {

	int unsupportedExtensionTypeCode = 0x50;
	byte[] helloExtensionBytes;
	HelloExtensions helloExtensions;
	InetSocketAddress peerAddress;

	@Before
	public void setUp() throws UnknownHostException {
		peerAddress = new InetSocketAddress(InetAddress.getLoopbackAddress(), 5684);
	}

	@Test
	public void testSerializationDeserialization() throws HandshakeException {
		ClientCertificateTypeExtension ext = new ClientCertificateTypeExtension(true);
		ext.addCertificateType(CertificateType.X_509);
		ext.addCertificateType(CertificateType.RAW_PUBLIC_KEY);
		
		HelloExtensions extensions = new HelloExtensions();
		extensions.addExtension(ext);
		byte[] serializedExtension = extensions.toByteArray();
		
		HelloExtensions deserializedExt = HelloExtensions.fromByteArray(serializedExtension, peerAddress);
		ClientCertificateTypeExtension certTypeExt = (ClientCertificateTypeExtension)
				deserializedExt.getExtensions().get(0);
		assertTrue(certTypeExt.getCertificateTypes().size() == 2);
		
	}

	@Test
	public void testFromByteArrayIgnoresUnknownExtensionTypes() throws HandshakeException {
		givenAMixOfSupportedAndUnsupportedHelloExtensions();
		whenDeserializingFromByteArray();
		assertThatSupportedExtensionTypesHaveBeenDeserialized();
	}
	
	@Test
	public void testToByteArrayReturnsEmptyByteArrayIfNoExtensionsAreSet() {
		givenAnEmptyExtensionsObject();
		whenSerializingToByteArray();
		assertThat(helloExtensionBytes.length, is(0));
	}
	
	private void assertThatSupportedExtensionTypesHaveBeenDeserialized() {
		assertNotNull(helloExtensions.getExtensions());
		assertTrue(containsExtensionType(
				ExtensionType.CLIENT_CERT_TYPE.getId(), helloExtensions.getExtensions()));
		assertTrue(containsExtensionType(
				ExtensionType.SERVER_CERT_TYPE.getId(), helloExtensions.getExtensions()));
		assertFalse(containsExtensionType(
				unsupportedExtensionTypeCode, helloExtensions.getExtensions()));
	}
	
	private void givenAMixOfSupportedAndUnsupportedHelloExtensions() {
		int length = 0;
		List<byte[]> extensions = new LinkedList<>();
		// a supported client certificate type extension
		byte[] ext = DtlsTestTools.newClientCertificateTypesExtension(CertificateType.X_509.getCode());
		length += ext.length;
		extensions.add(ext);
		// extension type 0x50 is not defined by IANA
		DatagramWriter writer = new DatagramWriter();
		writer.writeBytes(DtlsTestTools.newHelloExtension(
				unsupportedExtensionTypeCode, new byte[] { (byte) 0x12 }));
		ext = writer.toByteArray();
		length += ext.length;
		extensions.add(ext);
		// a supported server certificate type extension
		ext = DtlsTestTools.newServerCertificateTypesExtension(CertificateType.X_509.getCode());
		length += ext.length;
		extensions.add(ext);

		writer = new DatagramWriter();
		writer.write(length, HelloExtensions.LENGTH_BITS);
		for (byte[] extension : extensions) {
			writer.writeBytes(extension);
		}
		helloExtensionBytes = writer.toByteArray();
	}

	private void givenAnEmptyExtensionsObject() {
		helloExtensions = new HelloExtensions();
	}

	private void whenSerializingToByteArray() {
		helloExtensionBytes = helloExtensions.toByteArray();
	}

	private void whenDeserializingFromByteArray() throws HandshakeException {
		helloExtensions = HelloExtensions.fromByteArray(helloExtensionBytes, peerAddress);
	}

	private boolean containsExtensionType(int type, List<HelloExtension> extensions) {
		for (HelloExtension ext : extensions) {
			if (ext.getType().getId() == type) {
				return true;
			}
		}
		return false;
	}
}
