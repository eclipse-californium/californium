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
 *    Kai Hudalla, Bosch Software Innovations GmbH
 *    Kai Hudalla (Bosch Software Innovations GmbH) - adapt to HelloExtensions changes
 *    Achim Kraus (Bosch Software Innovations GmbH) - Replace getLocalHost() by
 *                                                    getLoopbackAddress()
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.HelloExtension.ExtensionType;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class HelloExtensionsTest {

	int unsupportedExtensionTypeCode = 0x50;
	byte[] helloExtensionBytes;
	HelloExtensions helloExtensions;

	@Test
	public void testSerializationDeserialization() throws HandshakeException {
		ClientCertificateTypeExtension ext = new ClientCertificateTypeExtension(Arrays.asList(CertificateType.X_509, CertificateType.RAW_PUBLIC_KEY));

		HelloExtensions extensions = new HelloExtensions();
		extensions.addExtension(ext);
		DatagramWriter writer = new DatagramWriter();
		extensions.writeTo(writer);
		byte[] serializedExtension = writer.toByteArray();

		HelloExtensions deserializedExt = HelloExtensions.fromReader(new DatagramReader(serializedExtension));
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

	@Test
	public void testFailOnDuplicateExtensionTypes() {
		givenDuplicateHelloExtensions();
		try {
			whenDeserializingFromByteArray();
			fail("defect not detected!");
		} catch (HandshakeException ex) {
			assertThat(ex.getAlert().getLevel(), is(AlertLevel.FATAL));
			assertThat(ex.getAlert().getDescription(), is(AlertDescription.DECODE_ERROR));
		}
	}

	@Test
	public void testFailOnBrokenExtension() {
		givenBrokenHelloExtensions();
		try {
			whenDeserializingFromByteArray();
			fail("defect not detected!");
		} catch (HandshakeException ex) {
			assertThat(ex.getAlert().getLevel(), is(AlertLevel.FATAL));
			assertThat(ex.getAlert().getDescription(), is(AlertDescription.DECODE_ERROR));
		}
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
		writer.write(length, HelloExtensions.OVERALL_LENGTH_BITS);
		for (byte[] extension : extensions) {
			writer.writeBytes(extension);
		}
		helloExtensionBytes = writer.toByteArray();
	}

	private void givenDuplicateHelloExtensions() {
		int length = 0;
		List<byte[]> extensions = new LinkedList<>();
		// a supported client certificate type extension
		byte[] ext = DtlsTestTools.newClientCertificateTypesExtension(CertificateType.X_509.getCode());
		length += ext.length;
		extensions.add(ext);
		// again supported client certificate type extension
		length += ext.length;
		extensions.add(ext);

		DatagramWriter writer = new DatagramWriter();
		writer.write(length, HelloExtensions.OVERALL_LENGTH_BITS);
		for (byte[] extension : extensions) {
			writer.writeBytes(extension);
		}
		helloExtensionBytes = writer.toByteArray();
	}

	private void givenBrokenHelloExtensions() {
		int length = 0;
		List<byte[]> extensions = new LinkedList<>();
		// a supported client certificate type extension
		byte[] ext = newBrokenClientCertificateTypesExtension(CertificateType.X_509.getCode());
		length += ext.length;
		extensions.add(ext);

		// a supported server certificate type extension
		ext = DtlsTestTools.newServerCertificateTypesExtension(CertificateType.X_509.getCode());
		length += ext.length;
		extensions.add(ext);

		DatagramWriter writer = new DatagramWriter();
		writer.write(length, HelloExtensions.OVERALL_LENGTH_BITS);
		for (byte[] extension : extensions) {
			writer.writeBytes(extension);
		}
		helloExtensionBytes = writer.toByteArray();
	}

	private void givenAnEmptyExtensionsObject() {
		helloExtensions = new HelloExtensions();
	}

	private void whenSerializingToByteArray() {
		DatagramWriter writer = new DatagramWriter();
		helloExtensions.writeTo(writer);
		helloExtensionBytes = writer.toByteArray();
	}

	private void whenDeserializingFromByteArray() throws HandshakeException {
		helloExtensions = HelloExtensions.fromReader(new DatagramReader(helloExtensionBytes));
	}

	private boolean containsExtensionType(int type, List<HelloExtension> extensions) {
		for (HelloExtension ext : extensions) {
			if (ext.getType().getId() == type) {
				return true;
			}
		}
		return false;
	}

	private static byte[] newBrokenClientCertificateTypesExtension(int... types) {
		DatagramWriter writer = new DatagramWriter();
		writer.write(types.length + 1, 8);
		for (int type : types) {
			writer.write(type, 8);
		}
		return DtlsTestTools.newHelloExtension(19, writer.toByteArray());
	}

}
