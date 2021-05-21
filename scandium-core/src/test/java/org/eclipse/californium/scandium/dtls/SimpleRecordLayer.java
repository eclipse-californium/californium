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

import java.net.DatagramPacket;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.DatagramReader;

public class SimpleRecordLayer implements RecordLayer {

	private final AtomicInteger droppedRecords = new AtomicInteger();
	private volatile Handshaker handshaker;
	private List<Record> flight = new ArrayList<Record>();

	public SimpleRecordLayer() {
	}

	@Override
	public void sendFlight(List<DatagramPacket> datagrams) {
		flight.clear();
		long timestamp = ClockUtil.nanoRealtime();
		for (DatagramPacket packet : datagrams) {
			DatagramReader reader = new DatagramReader(packet.getData(), packet.getOffset(), packet.getLength());
			List<Record> records = Record.fromReader(reader, handshaker.connectionIdGenerator, timestamp);
			for (Record record : records) {
				try {
					record.decodeFragment(handshaker.getDtlsContext().getReadState());
					flight.add(record);
				} catch (GeneralSecurityException e) {
					e.printStackTrace();
				} catch (HandshakeException e) {
					e.printStackTrace();
				}
			}
		}
	}

	public List<Record> getSentFlight() {
		return flight;
	}

	@Override
	public void processRecord(Record record, Connection connection) {
		Handshaker handshaker = this.handshaker;
		if (handshaker != null) {
			try {
				record.decodeFragment(handshaker.getDtlsContext().getReadState());
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

	@Override
	public void processHandshakeException(Connection connection, HandshakeException error) {
	}

	public void setHandshaker(Handshaker handshaker) {
		this.handshaker = handshaker;
	}

	@Override
	public boolean isRunning() {
		return true;
	}

	@Override
	public int getMaxDatagramSize(boolean ipv6) {
		return DEFAULT_ETH_MTU;
	}

	@Override
	public void dropReceivedRecord(Record record) {
		droppedRecords.incrementAndGet();
	}
}
