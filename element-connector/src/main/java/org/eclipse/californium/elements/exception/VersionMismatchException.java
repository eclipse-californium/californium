/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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
package org.eclipse.californium.elements.exception;

import org.eclipse.californium.elements.util.SerializationUtil;

/**
 * Exception indicating a version mismatch when reading data.
 * 
 * @see SerializationUtil#readStartItem(org.eclipse.californium.elements.util.DataStreamReader,
 *      int, int)
 * @since 3.0
 */
public class VersionMismatchException extends IllegalArgumentException {

	private static final long serialVersionUID = 1L;

	/**
	 * Mismatching read version.
	 */
	private final int readVersion;

	/**
	 * Create new instance.
	 * 
	 * @param readVersion mismatching read version
	 */
	public VersionMismatchException(int readVersion) {
		super();
		this.readVersion = readVersion;
	}

	/**
	 * Create new instance with message.
	 *
	 * @param message message
	 * @param readVersion mismatching read version
	 */
	public VersionMismatchException(String message, int readVersion) {
		super(message);
		this.readVersion = readVersion;
	}

	/**
	 * Gets mismatching read version.
	 * 
	 * @return mismatching read version
	 */
	public int getReadVersion() {
		return readVersion;
	}
}
