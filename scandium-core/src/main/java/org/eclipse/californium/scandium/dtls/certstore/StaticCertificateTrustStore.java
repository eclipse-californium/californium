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
import java.util.Collection;

/**
 * A Static Certificate store which contains all trusted certificates used by
 * handshakers.
 */
public class StaticCertificateTrustStore implements TrustedCertificateStore {

	private X509Certificate[] certificates;

	/**
	 * Create an empty store.
	 */
	public StaticCertificateTrustStore() {
		certificates = new X509Certificate[0];
	}
	
	public StaticCertificateTrustStore(Collection<? extends X509Certificate> trustedCertificates) {
		if(trustedCertificates == null) {
			certificates = new X509Certificate[0];
		} else {
			certificates = trustedCertificates.toArray(new X509Certificate[trustedCertificates.size()]);
		}
	}
	
	public StaticCertificateTrustStore(X509Certificate[] trustedCertificates) {
		if (trustedCertificates == null) {
			certificates = new X509Certificate[0];
		} else {
			certificates = trustedCertificates;
		}
	}

	@Override
	public X509Certificate[] getTrustedCertificate() {
		return certificates;
	}
	
	@Override
	public boolean isEmpty() {
		return certificates.length == 0;
	}
}
