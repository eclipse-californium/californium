/*******************************************************************************
 * Copyright (c) 2022 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium;

import org.eclipse.californium.elements.util.PublicAPIExtension;

/**
 * Health extended2 interface.
 * 
 * Add MAC errors and pending jobs.
 * 
 * @since 3.5
 */
@PublicAPIExtension(type = DtlsHealth.class)
public interface DtlsHealthExtended2 {

	/**
	 * Report receiving record with MAC error.
	 */
	void receivingMacError();

	/**
	 * Set number of pending incoming jobs.
	 * 
	 * @param count number of pending incoming jobs
	 */
	void setPendingIncomingJobs(int count);

	/**
	 * Set number of pending outgoing jobs.
	 * 
	 * @param count number of pending outgoing jobs
	 */
	void setPendingOutgoingJobs(int count);

	/**
	 * Set number of pending handshake result jobs.
	 * 
	 * @param count number of pending handshake result jobs
	 */
	void setPendingHandshakeJobs(int count);
}
