/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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

import java.net.InetSocketAddress;

import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.DTLSContext;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.SessionId;
import org.slf4j.MDC;

/**
 * Setup the logging MDC with the connection state.
 * 
 * Set:
 * 
 * {@code "PEER"} {@code "CONNECTION_ID"} {@code "WRITE_CONNECTION_ID"}
 * {@code "SESSION_ID"}
 * 
 * @since 2.4
 */
public class MdcConnectionListener implements ConnectionListener {

	@Override
	public void onConnectionEstablished(Connection connection) {
		// empty implementation
	}

	@Override
	public void onConnectionRemoved(Connection connection) {
		// empty implementation
	}

	@Override
	public boolean onConnectionUpdatesSequenceNumbers(Connection connection, boolean writeSequenceNumber) {
		// empty implementation, never close
		return false;
	}

	@Override
	public boolean onConnectionMacError(Connection connection) {
		// empty implementation, never close
		return false;
	}

	@Override
	public void beforeExecution(Connection connection) {
		if (DTLSConnector.MDC_SUPPORT) {
			InetSocketAddress peerAddress = connection.getPeerAddress();
			if (peerAddress != null) {
				MDC.put("PEER", StringUtil.toString(peerAddress));
			}
			ConnectionId cid = connection.getConnectionId();
			if (cid != null) {
				MDC.put("CONNECTION_ID", cid.getAsString());
			}
			DTLSContext context = connection.getEstablishedDtlsContext();
			if (context != null) {
				ConnectionId writeConnectionId = context.getWriteConnectionId();
				if (writeConnectionId != null && !writeConnectionId.isEmpty()) {
					MDC.put("WRITE_CONNECTION_ID", writeConnectionId.getAsString());
				}
			}
			DTLSSession session = connection.getSession();
			if (session != null) {
				SessionId sid = session.getSessionIdentifier();
				if (sid != null && !sid.isEmpty()) {
					MDC.put("SESSION_ID", sid.toString());
				}
			}
		}
	}

	@Override
	public void updateExecution(Connection connection) {
		beforeExecution(connection);
	}

	@Override
	public void afterExecution(Connection connection) {
		if (DTLSConnector.MDC_SUPPORT) {
			MDC.clear();
		}
	}

}
