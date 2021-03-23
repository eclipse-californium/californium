/*******************************************************************************
 * Copyright (c) 2019  Andrei-Marius Longhin and others.
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
 *     Andrei-Marius Longhin - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.exception;

/**
 * Exception indicating a connector-specific issue occurred
 */
public class ConnectorException extends Exception {

	private static final long serialVersionUID = 1L;

	/**
	 * Create new instance.
	 */
	public ConnectorException() {
		super();
	}

	/**
	 * Create new instance with message.
	 *
	 * @param message message
	 */
	public ConnectorException(String message) {
		super(message);
	}

	@Override
	public String getMessage() {
		String msg = super.getMessage();
		if (msg == null) {
			msg = getClass().getSimpleName();
		}
		return msg;
	}

}
