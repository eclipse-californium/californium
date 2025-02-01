/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium;

/**
 * Health interface for {@link DTLSConnector}.
 */
public interface DtlsHealth {

	/**
	 * Dump health data.
	 * 
	 * @param tag logging tag
	 * @param maxConnections maximum number of connections
	 * @param remainingCapacity remaining capacity for connections
	 */
	void dump(String tag, int maxConnections, int remainingCapacity);

	/**
	 * Check, if collecting health data is enabled.
	 * 
	 * @return {@code true}, if health is enabled, {@code false}, otherwise.
	 */
	boolean isEnabled();

	/**
	 * Report started handshake.
	 */
	void startHandshake();

	/**
	 * Report ended handshake.
	 * 
	 * @param success {@code true} for successful handshake, {@code false} for
	 *            failed handshake.
	 */
	void endHandshake(boolean success);

	/**
	 * Report receiving record
	 * 
	 * @param drop {@code true}, if record is dropped, {@code false}, if record
	 *            is received.
	 */
	void receivingRecord(boolean drop);

	/**
	 * Report sending record.
	 * 
	 * @param drop {@code true}, if record is dropped, {@code false}, if record
	 *            is to be sent.
	 */
	void sendingRecord(boolean drop);

	/**
	 * Set number of connections.
	 * 
	 * @param count number of connections
	 * 
	 * @since 4.0 (moved from obsolete DtlsHealthExtended)
	 */
	void setConnections(int count);

	/**
	 * Report receiving record with MAC error.
	 * 
	 * @since 4.0 (moved from obsolete DtlsHealthExtended2)
	 */
	void receivingMacError();

	/**
	 * Set number of pending incoming jobs.
	 * 
	 * @param count number of pending incoming jobs
	 * @since 4.0 (moved from obsolete DtlsHealthExtended2)
	 */
	void setPendingIncomingJobs(int count);

	/**
	 * Set number of pending outgoing jobs.
	 * 
	 * @param count number of pending outgoing jobs
	 * @since 4.0 (moved from obsolete DtlsHealthExtended2)
	 */
	void setPendingOutgoingJobs(int count);

	/**
	 * Set number of pending handshake result jobs.
	 * 
	 * @param count number of pending handshake result jobs
	 * @since 4.0 (moved from obsolete DtlsHealthExtended2)
	 */
	void setPendingHandshakeJobs(int count);

	/**
	 * Report missing application authorization.
	 * 
	 * @param rejected {@code true}, if authorization was rejected,
	 *            {@code false}, if the authorization is missing after a
	 *            timeout.
	 * @since 4.0
	 */
	void applicationAuthorizationRejected(boolean rejected);
}
