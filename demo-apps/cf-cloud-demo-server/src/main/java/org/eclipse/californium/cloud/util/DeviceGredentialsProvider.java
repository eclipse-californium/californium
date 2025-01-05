/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.cloud.util;

import org.eclipse.californium.scandium.auth.ApplicationLevelInfoSupplier;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.dtls.x509.CertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.CertificateVerifier;

/**
 * Device credentials provider.
 * 
 * @since 3.12
 */
public interface DeviceGredentialsProvider {

	/**
	 * Get PreSharedKey store.
	 * <p>
	 * The PreSharedKey store contains all valid identity and secret key pairs
	 * of the provisioned devices.
	 * 
	 * @return PreSharedKey store, or {@code null}, if not available.
	 */
	PskStore getPskStore();

	/**
	 * Get certificate verifier.
	 * <p>
	 * The certificate verifier is used to verify all received certificates from
	 * the devices.
	 * 
	 * @return certificate verifier, or {@code null}, if not available.
	 */
	CertificateVerifier getCertificateVerifier();

	/**
	 * Get certificate provider.
	 * <p>
	 * The certificate provider provides the certificate to identify this peer.
	 * 
	 * @return certificate provider, or {@code null}, if not available.
	 */
	CertificateProvider getCertificateProvider();

	/**
	 * Get additional information supplier.
	 * <p>
	 * Used to add additional device information to the principal representing
	 * the device.
	 * 
	 * @return additional information supplier, or {@code null}, if not
	 *         available.
	 */
	ApplicationLevelInfoSupplier getInfoSupplier();
}
