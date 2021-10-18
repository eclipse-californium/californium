/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
package org.eclipse.californium.scandium.dtls.x509;

/**
 * Setup for certificate configuration helper.
 * 
 * {@link CertificateProvider} and {@link NewAdvancedCertificateVerifier}
 * implementation may implement this interface as well in order to participate
 * in the automatic default configuration and configuration verification.
 * 
 * @since 3.0
 */
public interface ConfigurationHelperSetup {

	/**
	 * Setup the helper.
	 * 
	 * Add all public key, certificate chains, or trusted certificates to the
	 * provided helper.
	 * 
	 * @param helper configuration helper.
	 * @throws NullPointerException if the helper is {@code null}
	 */
	void setupConfigurationHelper(CertificateConfigurationHelper helper);

}
