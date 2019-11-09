/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove unused sendRecord
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove cancelRetransmissions
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.GeneralSecurityException;

public class SimpleRecordLayer implements RecordLayer {

	private volatile Handshaker handshaker;
	private DTLSFlight sentFlight;

	public SimpleRecordLayer() {
	}

	@Override
	public void sendFlight(DTLSFlight flight, Connection connection) {
		sentFlight = flight;
	}

	public DTLSFlight getSentFlight() {
		return sentFlight;
	}

	@Override
	public void processRecord(Record record, Connection connection) {
		Handshaker handshaker = this.handshaker;
		if (handshaker != null) {
			try {
				record.applySession(handshaker.getSession());
				handshaker.processMessage(record);
			} catch (HandshakeException e) {
				e.printStackTrace();
				throw new IllegalArgumentException(e);
			} catch (GeneralSecurityException e) {
				e.printStackTrace();
				throw new IllegalArgumentException(e);
			}
		}
	}

	public void setHandshaker(Handshaker handshaker) {
		this.handshaker = handshaker;
	}
}
