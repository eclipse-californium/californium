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

import org.eclipse.californium.scandium.dtls.cipher.CipherSuiteParameters.GeneralMismatch;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuiteParameters.CertificateBasedMismatch;

/**
 * @since 2.3
 */
public interface CipherSuiteSelector {

	/**
	 * Select cipher-suite and parameters.
	 * 
	 * Since 3.0, if no common parameter could be negotiated, use
	 * {@link CipherSuiteParameters#setGeneralMismatch(GeneralMismatch)} or
	 * {@link CipherSuiteParameters#setCertificateMismatch(CertificateBasedMismatch)}
	 * to indicate the mismatch cause.
	 * 
	 * @param parameters common cipher-suites and crypto parameters. On success,
	 *            the cipher-suite and parameters gets selected in this
	 *            argument.
	 * @return {@code true}, if a cipher-suite and parameters could be selected,
	 *         {@code false}, otherwise.
	 */
	boolean select(CipherSuiteParameters parameters);

}
