/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove unused sendRecord
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove cancelRetransmissions
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

public class SimpleRecordLayer implements RecordLayer {
	private DTLSFlight sentFlight;

	@Override
	public void sendFlight(DTLSFlight flight, Connection connection) {
		sentFlight = flight;
	}

	public DTLSFlight getSentFlight() {
		return sentFlight;
	}
}