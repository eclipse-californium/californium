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
 *    Achim Kraus (Bosch Software Innovations GmbH) - Initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;

/**
 * An debug {@code ResumptionSupportingConnectionStore} with dump and validate
 * methods.
 * 
 * Intended to be used for unit tests.
 * 
 * @since 3.5
 */
public interface DebugConnectionStore extends ResumptionSupportingConnectionStore {

	/**
	 * Set logging tag.
	 * 
	 * @param tag logging tag
	 * @return this connection store
	 */
	ResumptionSupportingConnectionStore setTag(String tag);

	/**
	 * Dump connections to logger. Intended to be used for unit tests.
	 */
	void dump();

	/**
	 * Dump connections to logger. Intended to be used for unit tests.
	 * 
	 * @param address address of connection to dump
	 */
	boolean dump(InetSocketAddress address);

	/**
	 * Validate connections. Intended to be used for unit tests.
	 */
	void validate();
}
