/*******************************************************************************
 * Copyright (c) 2017 RISE SICS.
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
 *    Ludwig Seitz (RISE SICS) - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.rpkstore;

import org.eclipse.californium.scandium.auth.RawPublicKeyIdentity;

/**
 * An interface for trust stores that provide trusted raw public keys to the
 * handshaker.
 * 
 * @author Ludwig Seitz
 *
 */
public interface TrustedRpkStore {

	/**
	 * Is the given raw public key trusted?
	 * 
	 * @param id  the identity of the public key
	 * 
	 * @return true if trusted, false otherwise
	 */
	public boolean isTrusted(RawPublicKeyIdentity id);

}
