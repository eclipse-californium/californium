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
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import org.eclipse.californium.elements.util.Bytes;

/**
 *
 * Provides byte arrays with identification.
 */
public class ByteId extends Bytes {

	public ByteId(byte[] id) {
		super(id);
	}
	
	@Override
	public String toString() {
		return new StringBuilder("ByteId=").append(getAsString()).toString();
	}
}
