/********************************************************************************
 * Copyright (c) 2025 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.elements.exception;

/**
 * This class indicates missing application authorization for anonymous clients.
 * 
 * @since 4.0
 */
public class MissingApplicationAuthorizationException extends Exception {

	private static final long serialVersionUID = 9209664901497784712L;

	private final boolean rejected;

	/**
	 * Creates missing application authorization exception.
	 * 
	 * @param rejected {@code true}, if application rejected the authorization,
	 *            {@code false}, if the authorization timed out.
	 */
	public MissingApplicationAuthorizationException(boolean rejected) {
		super(rejected ? "rejected application authorization!" : "missing application authorization!");
		this.rejected = rejected;
	}

	/**
	 * Checks the cause of the missing application authorization
	 * 
	 * @return {@code true}, if application rejected the authorization,
	 *         {@code false}, if the authorization timed out.
	 */
	public boolean isRejected() {
		return rejected;
	}
}
