/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.extplugtests.resources;

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
	 * Create instance for received request.
	 * 
	 * @param requestId request id received with message
	 * @param requestTime system time in milliseconds when receiving the message
	 */
	public RequestInformation(String requestId, long requestTime) {
		this.requestId = requestId;
		this.requestTime = requestTime;
	}
}
