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

/**
 * Filter for incoming datagrams.
 * 
 * @since 3.5
 */
public interface DatagramFilter {

	/**
	 * Check and filter incoming datagram.
	 * 
	 * @param packet incoming datagram
	 * @return {@code true}, continue to process datagram, {@code false} to drop
	 *         it.
	 */
	boolean onReceiving(DatagramPacket packet);
}
