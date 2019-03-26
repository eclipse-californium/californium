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
 *    Tobias Andersson (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * Provides byte arrays with identification.
 */

public class ByteId {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(ByteId.class.getName());

	private byte[] id;

	public ByteId(byte[] id) {
		if (id != null) {
			this.id = id;
		} else {
			LOGGER.error(ErrorDescriptions.TOKEN_NULL);
			throw new NullPointerException(ErrorDescriptions.TOKEN_NULL);
		}
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(id);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ByteId other = (ByteId) obj;
		return Arrays.equals(id, other.id);
	}
}
