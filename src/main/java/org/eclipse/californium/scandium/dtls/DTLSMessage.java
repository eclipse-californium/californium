/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;



/**
 * Defines the DTLS message interface used by {@link Record} and implemented by
 * the 4 message {@link ContentType}: {@link ChangeCipherSpecMessage},
 * {@link AlertMessage}, {@link HandshakeMessage} and {@link ApplicationMessage}
 * .
 */
public interface DTLSMessage {

	/**
	 * 
	 * @return the byte representation of this DTLS message.
	 */
	public byte[] toByteArray();
}
