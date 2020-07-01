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
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.net.InetSocketAddress;
import java.nio.Buffer;
import java.nio.ByteBuffer;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.DatagramReader;
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
	byte[] emptyExtension = new byte[]{
			(byte) 0x00, (byte) 0x00, // extension code 0x0000
			(byte) 0x00, (byte) 0x00  // length: 0 bytes
	};

	/**
	 * Verifies that an empty extension is serialized correctly.
	 */
	@Test
	public void testEmptyServerNameExtensionContainsNoNames() {

		extension = ServerNameExtension.emptyServerNameIndication();

		assertThat(extension.getServerNames(), is(nullValue()));
		assertThat(extension.getLength(), is(4)); // 2 bytes extension type + 2 bytes extension length

		assertThat(extension.toByteArray(), is(emptyExtension));
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
		ServerNameExtension ext = ServerNameExtension.forServerNames(ServerNames.newInstance("iot.eclipse.org"));
		ByteBuffer b = ByteBuffer.allocate(1024);
		writeLength(ext.getLength(), b); //extension length
		b.put(ext.toByteArray());
		((Buffer)b).flip();
		serverNameStructure = new byte[b.limit()];
		b.get(serverNameStructure);

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

	private void givenAnEmptyServerNameExtensionStruct() {

		ByteBuffer b = ByteBuffer.allocate(1024);
		writeLength(emptyExtension.length, b); // length of extensions list
		b.put(emptyExtension);
		((Buffer)b).flip();
		serverNameStructure = new byte[b.limit()];
		b.get(serverNameStructure);
	}

	private void givenAServerNameExtensionStruct(final byte nameType, final byte[] name) {

		ByteBuffer nameEntry = ByteBuffer.allocate(1024);
		nameEntry.put(nameType); // name type
		writeLength(name.length, nameEntry);
		nameEntry.put(name);
		((Buffer)nameEntry).flip();

		ByteBuffer ext = ByteBuffer.allocate(1024);
		ext.put((byte) 0x00).put((byte) 0x00); // type code 0x0000 = server_name
		writeLength(nameEntry.limit() + 2, ext); //extension_data length
		writeLength(nameEntry.limit(), ext); // server name list length
		ext.put(nameEntry);
		((Buffer)ext).flip();

		ByteBuffer b = ByteBuffer.allocate(1024);
		writeLength(ext.limit(), b); // length of extensions list
		b.put(ext);
		((Buffer)b).flip();
		serverNameStructure = new byte[b.limit()];
		b.get(serverNameStructure);
	}

	private void whenParsingTheExtensionStruct() throws HandshakeException {
		HelloExtensions helloExtensions = HelloExtensions.fromReader(new DatagramReader(serverNameStructure), new InetSocketAddress(0));
		extension = (ServerNameExtension) helloExtensions.getExtension(ExtensionType.SERVER_NAME);
	}

	private static void writeLength(final int length, final ByteBuffer buf) {
		buf.put((byte) (length >> 8 & 0xFF)).put((byte) (length & 0xFF));
	}
}
