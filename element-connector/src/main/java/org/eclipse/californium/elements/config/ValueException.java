/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.config;

/**
 * Value exception.
 * 
 * Message contains the value and details about the failure.
 * 
 * @see DocumentedDefinition#parseValue(String)
 * @see DocumentedDefinition#checkValue(Object)
 * @since 3.0
 */
public class ValueException extends Exception {

	private static final long serialVersionUID = 3254131344341974160L;

	/**
	 * Create value exception with details description.
	 * 
	 * @param description message with value and details description
	 */
	public ValueException(String description) {
		super(description);
	}
}
