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
 *                    derived from ECDHECryptography
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

/**
 * @since 2.3
 */
public interface CipherSuiteSelector {

	/**
	 * Select ciphersuite and parameters.
	 * 
	 * @param parameters common ciphersuites and crypto parameters. On success,
	 *            the ciphersuite and parameters gets selected in this argument.
	 * @return {@code true}, if a ciphersuite and parameters could be selected,
	 *         {@code false}, otherwise.
	 */
	boolean select(CipherSuiteParameters parameters);

}
