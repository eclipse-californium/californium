/*******************************************************************************
 * Copyright (c) 2018 Sierra Wireless and others.
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
 *     Sierra Wireless - initial API and implementation
 *******************************************************************************/
package org.eclipse.californium.scandium.dtls.certstore;

import java.security.cert.X509Certificate;

/**
 * A certificate store which contains all trusted certificates used by
 * handshakers.
 * 
 */
public interface TrustedCertificateStore {

	/**
	 * @return all trusted certificates
	 */
	X509Certificate[] getTrustedCertificate();
	
	/**
	 *  @return true if the store is empty
	 */
	boolean isEmpty();
}
