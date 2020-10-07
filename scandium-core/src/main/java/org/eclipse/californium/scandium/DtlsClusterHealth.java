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

/**
 * Health interface for {@link DtlsClusterConnector}.
 * 
 * @since 2.5
 */
public interface DtlsClusterHealth extends DtlsHealth {

	/**
	 * Report forwarding (CID) message.
	 */
	void forwardMessage();

	/**
	 * Report processing of forwarded (CID) message.
	 */
	void processForwardedMessage();

	/**
	 * Report backwarding (CID) message.
	 */
	void backwardMessage();

	/**
	 * Report sending backwarded (CID) message.
	 */
	void sendBackwardedMessage();

	/**
	 * Report dropped forward (CID) message.
	 */
	void dropForwardMessage();

	/**
	 * Report dropped backward (CID) message.
	 */
	void dropBackwardMessage();

	/**
	 * Report bad forward (CID) message.
	 */
	void badForwardMessage();

	/**
	 * Report bad backward (CID) message.
	 */
	void badBackwardMessage();

	/**
	 * Report sending cluster management message.
	 */
	void sendingClusterManagementMessage();

	/**
	 * Report receiving cluster management message.
	 */
	void receivingClusterManagementMessage();

}
