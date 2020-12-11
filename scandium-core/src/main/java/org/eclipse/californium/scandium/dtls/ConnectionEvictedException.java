/*******************************************************************************
 * Copyright (c) 2020 Sierra Wireless and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

/**
 * Raised when a connection is evicted from
 * {@link ResumptionSupportingConnectionStore}
 * 
 * @since 2.3
 */
public class ConnectionEvictedException extends DtlsException {

	private static final long serialVersionUID = 1L;

	public ConnectionEvictedException(String message) {
		super(message);
	}
}
