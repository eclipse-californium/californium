/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;

/**
 * Thread local CertificateFactory.
 * 
 * Uses {@link ThreadLocal} to cache calls to
 * {@link CertificateFactory#getInstance(String)}.
 * 
 * @since 2.4
 */
public class ThreadLocalCertificateFactory extends ThreadLocalCrypto<CertificateFactory> {

	/**
	 * Create thread local CertificateFactory.
	 * 
	 * Try to instance the CertificateFactory for the provided algorithm.
	 * 
	 * @param algorithm algorithm. Passed to
	 *            {@link CertificateFactory#getInstance(String)}.
	 * @see ThreadLocalCrypto
	 */
	public ThreadLocalCertificateFactory(final String algorithm) {
		super(new Factory<CertificateFactory>() {

			@Override
			public CertificateFactory getInstance() throws GeneralSecurityException {
				return CertificateFactory.getInstance(algorithm);
			}

		});
	}

}
