/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
package org.eclipse.californium.elements;

/**
 * Exception indicating, that the connector doesn't support multicast messages.
 */
public class MulticastNotSupportedException extends Exception {

	private static final long serialVersionUID = 1L;

	/**
	 * Create new instance.
	 */
	public MulticastNotSupportedException() {

	}

	/**
	 * Create new instance with message.
	 * 
	 * @param message message
	 */
	public MulticastNotSupportedException(String message) {
		super(message);
	}
}
