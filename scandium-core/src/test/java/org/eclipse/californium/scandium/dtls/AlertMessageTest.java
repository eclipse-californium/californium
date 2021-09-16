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

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class AlertMessageTest {

	private static final byte UNKNOWN_LEVEL = 0x20;
	private static final byte UNKNOWN_DESCRIPTION = (byte) 0xFD;

	/**
	 * Verifies that an alert message can be parsed successfully.
	 */
	@Test
	public void testFromByteArraySuccessfullyParsesLevelAndDescription() throws Exception {
		// GIVEN a record containing a fatal handshake failure alert mesage
		byte[] fragment = new byte[]{AlertLevel.FATAL.getCode(), AlertDescription.HANDSHAKE_FAILURE.getCode()};

		// WHEN parsing the record
		AlertMessage alert = AlertMessage.fromByteArray(fragment);

		// THEN the level is FATAL and the description is HANDSHAKE_FAILURE
		assertThat(alert.getLevel(), is(AlertLevel.FATAL));
		assertThat(alert.getDescription(), is(AlertDescription.HANDSHAKE_FAILURE));
	}

	/**
	 * Verifies that an unknown alert level value results in a {@code HandshakeException}
	 * being thrown.
	 */
	@Test
	public void testFromByteArrayThrowsExceptionForUnknownLevel() throws GeneralSecurityException {
		// GIVEN a record containing an alert message with an undefined alert level
		byte[] fragment = new byte[]{UNKNOWN_LEVEL, AlertDescription.HANDSHAKE_FAILURE.getCode()};

		// WHEN parsing the record
		try {
			AlertMessage.fromByteArray(fragment);
			fail("Should have thrown " + HandshakeException.class.getName());

			// THEN a fatal handshake exception will be thrown
		} catch (HandshakeException e) {
			assertThat(e.getAlert().getLevel(), is(AlertLevel.FATAL));
		}
	}

	/**
	 * Verifies that an unknown description level value results in a {@code HandshakeException}
	 * being thrown.
	 */
	@Test
	public void testFromByteArrayThrowsExceptionForUnknownDescription() throws GeneralSecurityException {
		// GIVEN a record containing an alert message with an undefined description level
		byte[] fragment = new byte[]{AlertLevel.WARNING.getCode(), UNKNOWN_DESCRIPTION};

		// WHEN parsing the record
		try {
			AlertMessage.fromByteArray(fragment);
			fail("Should have thrown " + HandshakeException.class.getName());

			// THEN a fatal handshake exception will be thrown
		} catch (HandshakeException e) {
			assertThat(e.getAlert().getLevel(), is(AlertLevel.FATAL));
		}
	}

	@Test
	public void testSerializeWithHandshakeException() throws IOException, ClassNotFoundException {
		AlertMessage alert = new AlertMessage(AlertLevel.WARNING, AlertDescription.HANDSHAKE_FAILURE);
		HandshakeException exception = new HandshakeException("test", alert);

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ObjectOutputStream oout = new ObjectOutputStream(out);
		oout.writeObject(exception);

		ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
		ObjectInputStream oin = new ObjectInputStream(in);
		Object object = oin.readObject();
		assertThat(object, is(instanceOf(HandshakeException.class)));
		HandshakeException readException = (HandshakeException) object;
		assertThat(readException.getMessage(), is(exception.getMessage()));
		assertThat(readException.getAlert().getLevel(), is(exception.getAlert().getLevel()));
		assertThat(readException.getAlert().getDescription(), is(exception.getAlert().getDescription()));
	}
}
