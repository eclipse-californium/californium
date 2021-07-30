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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.HelloExtension.ExtensionType;
import org.eclipse.californium.scandium.util.ServerName;
import org.eclipse.californium.scandium.util.ServerNames;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Test cases verifying serialization and deserialization of the {@link ServerNameExtension}.
 *
 */
@Category(Small.class)
public class ServerNameExtensionTest {

	byte[] serverNameStructure;
	ServerNameExtension extension;
	byte[] iotEclipseOrg = "iot.eclipse.org".getBytes(ServerName.CHARSET);

	/**
	 * Verifies that an empty extension is serialized correctly.
	 */
	@Test
	public void testEmptyServerNameExtensionContainsNoNames() {

		extension = ServerNameExtension.emptyServerNameIndication();

		assertThat(extension.getServerNames(), is(nullValue()));
		assertThat(extension.getExtensionLength(), is(0));
		DatagramWriter writer = new DatagramWriter();
		extension.writeExtensionTo(writer);
		assertThat(writer.size(), is(0));
	}

	/**
	 * Verifies that an empty extension deserialized from its byte representation
	 * doesn't contain any names.
	 * 
	 * @throws HandshakeException if deserializaiton fails.
	 */
	@Test
	public void testFromByteArrayCreatesEmptyExtension() throws HandshakeException {

		// GIVEN an empty extension structure
		givenAnEmptyServerNameExtensionStruct();

		whenParsingTheExtensionStruct();

		// THEN assert that the extension object does not contain any names
		assertThat(extension.getServerNames(), is(nullValue()));
	}

	/**
	 * Verifies that the result of serializing an extension object to a byte array can
	 * be parsed again successfully into the same extension object.
	 *  
	 * @throws HandshakeException if the extension cannot be parsed.
	 */
	@Test
	public void testToByteArrayResultCanBeParsedIntoExtensionAgain() throws HandshakeException {

		// GIVEN a serialized server name extension object
		DatagramWriter writer = new DatagramWriter();

		HelloExtensions extensions = new HelloExtensions();
		extensions.addExtension(ServerNameExtension.forServerNames(ServerNames.newInstance("iot.eclipse.org")));
		extensions.writeTo(writer);
		serverNameStructure = writer.toByteArray();

		// WHEN parsing the serialized extension
		whenParsingTheExtensionStruct();

		// THEN assert that the contained host name matches
		assertThat(extension.getServerNames(), is(notNullValue()));
		assertThat(extension.getServerNames().get(ServerName.NameType.HOST_NAME), is(iotEclipseOrg));
	}

	/**
	 * Verifies that a byte array representation containing a host name can be parsed successfully.
	 * 
	 * @throws HandshakeException if the parsing fails.
	 */
	@Test
	public void testFromByteArrayReadsHostName() throws HandshakeException {

		// GIVEN a server name extension data struct with host name
		givenAServerNameExtensionStruct((byte) 0x00, iotEclipseOrg);

		whenParsingTheExtensionStruct();

		// THEN assert that server names contain host name entry
		assertThat(extension.getServerNames().get(ServerName.NameType.HOST_NAME), is(iotEclipseOrg));
	}

	/**
	 * Verifies that an illegal name type code results in a fatal HandshakeException being thrown.
	 */
	@Test
	public void testFromByteArrayDetectsIllegalCode() {

		// given a server name extension data struct with host name and non-existing name type code
		givenAServerNameExtensionStruct((byte) 0x01, iotEclipseOrg); // 0x01 is not defined

		try {
			whenParsingTheExtensionStruct();
			fail("Should have thrown HandshakeException");
		} catch (HandshakeException e) {
			// then a HandshakeException should indicate illegal code
			assertThat(e.getAlert().getDescription(), is(AlertMessage.AlertDescription.ILLEGAL_PARAMETER));
			assertThat(e.getAlert().getLevel(), is(AlertMessage.AlertLevel.FATAL));
		}
	}

	@Test
	public void testDoubleServerNameType() {
		ServerNames names = ServerNames.newInstance();
		ServerName name1 = ServerName.fromHostName("server1");
		ServerName name2 = ServerName.fromHostName("server2");
		names.add(name1);
		try {
			names.add(name2);
			fail("didn't detect double hostname.");
		} catch (IllegalArgumentException ex) {
		}
	}

	private void givenAnEmptyServerNameExtensionStruct() {
		DatagramWriter writer = new DatagramWriter();
		writer.write(4, 16);
		writer.write(HelloExtension.ExtensionType.SERVER_NAME.getId(), 16);
		writer.write(0, 16);
		serverNameStructure = writer.toByteArray();
	}

	private void givenAServerNameExtensionStruct(final byte nameType, final byte[] name) {
		DatagramWriter writer = new DatagramWriter();
		writer.write(name.length + 9, 16); // id + length + length + type + length
		writer.write(HelloExtension.ExtensionType.SERVER_NAME.getId(), 16);
		writer.write(name.length + 2 + 1 + 2, 16); // length + type +  length
		writer.write(name.length + 1 + 2, 16); // type + length
		writer.writeByte(nameType);
		writer.writeVarBytes(name, 16);

		serverNameStructure = writer.toByteArray();
	}

	private void whenParsingTheExtensionStruct() throws HandshakeException {
		HelloExtensions helloExtensions = HelloExtensions.fromReader(new DatagramReader(serverNameStructure));
		extension = (ServerNameExtension) helloExtensions.getExtension(ExtensionType.SERVER_NAME);
	}
}
