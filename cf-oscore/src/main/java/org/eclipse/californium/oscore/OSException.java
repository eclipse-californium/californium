/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
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
 *    Joakim Brorsson
 *    Tobias Andersson (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

/**
 * 
 * Exception occurring during OSCORE mechanics
 *
 */
public class OSException extends Exception {

	/**
	 * Serial version UID
	 */
	private static final long serialVersionUID = -6170819091814613099L;

	/**
	 * Constructor, sets the message
	 * 
	 * @param message the message
	 */
	public OSException(String message) {
		super(message);
	}
}
