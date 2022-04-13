/*******************************************************************************
 * Copyright (c) 2022 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium;

import java.net.DatagramPacket;

import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.ProtocolVersion;
import org.eclipse.californium.scandium.dtls.Record;

/**
 * Filter valid DTLS incoming datagrams.
 * 
 * @since 3.5
 */
public class DtlsDatagramFilter implements DatagramFilter {

	public boolean onReceiving(DatagramPacket packet) {
		if ( packet.getLength() < Record.RECORD_HEADER_BYTES) {
			// drop, too short
			return false;
		}
		byte[] data = packet.getData();
		int offset = packet.getOffset();
		ContentType contentType = ContentType.getTypeByValue(data[offset]);
		if (contentType == null) {
			// drop
			return false;
		}
		if (data[offset + 3] != 0 || (data[offset + 4] & 0xff) > 1 || data[offset + 5] != 0) {
			// drop epoch > 1, seqn >= 0x0100000000
			return false;
		}
		if (contentType == ContentType.HANDSHAKE || contentType == ContentType.ALERT) {
			return true;
		}
		int major = 0xff & data[offset + 1];
		int minor = 0xff & data[offset + 2];
		if (major == ProtocolVersion.MAJOR_1 && minor == ProtocolVersion.MINOR_2) {
			return true;
		}
		// drop
		return false;
	}
}
