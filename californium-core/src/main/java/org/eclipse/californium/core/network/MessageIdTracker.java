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
 *    Bosch Software Innovations - initial creation
 *                                 (derived from MessageIdTracker)
 ******************************************************************************/
package org.eclipse.californium.core.network;

/**
 * A interface helper for keeping track of message IDs.
 */
public interface MessageIdTracker {

	/**
	 * Total number of MIDs.
	 */
	final int TOTAL_NO_OF_MIDS = 1 << 16;

	/**
	 * Gets the next usable message ID.
	 * 
	 * @return a message ID or {@code -1} if all message IDs are in use
	 *         currently.
	 */
	int getNextMessageId();
}
