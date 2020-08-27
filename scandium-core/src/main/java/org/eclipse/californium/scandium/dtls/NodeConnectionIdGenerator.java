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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

/**
 * Connection id generator encoding a node ID into the connection ID.
 * 
 * @since 2.5
 */
public interface NodeConnectionIdGenerator extends ConnectionIdGenerator {

	/**
	 * Get node ID of generator.
	 * 
	 * @return node ID
	 */
	int getNodeId();

	/**
	 * Get node ID encoded in cid.
	 * 
	 * @param cid cid
	 * @return node ID
	 */
	int getNodeId(ConnectionId cid);

}
