/*******************************************************************************
 * Copyright (c) 2020 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.core.observe;

/**
 * Exception indicating, that a observation could not be stored.
 * 
 * @see ObservationStore
 * @since 2.1
 */
public class ObservationStoreException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	/**
	 * Create new instance with message.
	 * 
	 * @param message message
	 */
	public ObservationStoreException(String message) {
		super(message);
	}
}
