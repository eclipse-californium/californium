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
 *                    Derived for californium-core CheckCondition
 ******************************************************************************/
package org.eclipse.californium.elements.util;

/**
 * Interface to "poll" on conditions, where the API doesn't support a
 * notification.
 * 
 * @since 2.3
 */
public interface TestCondition {

	/**
	 * Check, if the condition is fulfilled.
	 * 
	 * Intended to be implemented in a non blocking and very fast fashion!
	 * 
	 * @return {@code true}, if the condition is fulfilled, {@code false},
	 *         otherwise
	 * @throws IllegalStateException if the condition will not be fulfilled.
	 *             Caused, if something occurs, which makes it impossible, that
	 *             the condition is going to be fulfilled.
	 */
	boolean isFulFilled() throws IllegalStateException;
}
