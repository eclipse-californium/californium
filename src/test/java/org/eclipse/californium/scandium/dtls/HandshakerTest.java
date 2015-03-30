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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class HandshakerTest {

	InetSocketAddress endpoint = InetSocketAddress.createUnresolved("localhost", 10000);
	Handshaker handshaker;
	DTLSSession session;
	
	@Before
	public void setUp() throws Exception {
		session = new DTLSSession(endpoint, false);
		handshaker = new Handshaker(false, session, null, 1500) {
			@Override
			public DTLSFlight getStartHandshakeMessage() {
				return new DTLSFlight(session);
			}
			
			@Override
			protected DTLSFlight doProcessMessage(Record record)
					throws HandshakeException {
				return new DTLSFlight(session);
			}
		};
	}

	@Test
	public void testProcessMessageDiscardsDuplicateRecord() throws HandshakeException {
		Record record0 = createRecord(0, 0);
		Record record1 = createRecord(0, 1);
	
		DTLSFlight flight = handshaker.processMessage(record0);
		Assert.assertNotNull(flight);
		Assert.assertTrue(flight.getMessages().isEmpty());

		// send record with same sequence number again
		flight = handshaker.processMessage(record0);
		Assert.assertNull(flight);

		// send record with next sequence number
		flight = handshaker.processMessage(record1);
		Assert.assertNotNull(flight);
		}

	private Record createRecord(long epoch, long sequenceNo) {
		byte[] clientHello = DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(),
				session.getWriteEpoch(), session.getSequenceNumber(), new byte[10]);
		return Record.fromByteArray(clientHello).get(0);
	}
}
