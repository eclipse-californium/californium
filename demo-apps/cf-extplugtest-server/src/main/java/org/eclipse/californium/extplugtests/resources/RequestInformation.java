/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.extplugtests.resources;

import java.net.InetSocketAddress;

/**
 * Request information. Provides received {@link #requestId} together with
 * {@link #requestTime} (system time in milliseconds).
 */
public class RequestInformation {

	/**
	 * Received request id.
	 */
	public final String requestId;
	/**
	 * System time of receiving the request.
	 */
	public final long requestTime;
	/**
	 * Source endpoint.
	 */
	public final byte[] sourceAddress;
	public final short sourcePort;

	/**
	 * Create instance for received request.
	 * 
	 * @param requestId   request id received with message
	 * @param requestTime system time in milliseconds when receiving the message
	 * @param source      source endpoint, May be {@code null}, if it should not be
	 *                    tracked.
	 */
	public RequestInformation(String requestId, long requestTime, InetSocketAddress source) {
		this.requestId = requestId;
		this.requestTime = requestTime;
		if (source == null) {
			this.sourceAddress = null;
			this.sourcePort = 0;
		} else {
			this.sourceAddress = source.getAddress().getAddress();
			this.sourcePort = (short) source.getPort();
		}
	}
}
