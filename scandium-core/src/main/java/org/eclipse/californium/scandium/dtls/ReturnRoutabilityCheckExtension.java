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
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;

/**
 * Return routability check extension.
 * <p>
 * See <a href= "https://tlswg.org/dtls-rrc/draft-ietf-tls-dtls-rrc.html" target
 * ="_blank">dtls-rrc/draft-ietf-tls-dtls-rrc, Return Routability Check for DTLS
 * 1.2 and DTLS 1.3</a>.
 * 
 * @since 3.12
 */
public final class ReturnRoutabilityCheckExtension extends HelloExtension {

	public static ReturnRoutabilityCheckExtension INSTANCE = new ReturnRoutabilityCheckExtension();

	/**
	 * Create extended master secret extension.
	 */
	private ReturnRoutabilityCheckExtension() {
		super(ExtensionType.RETURN_ROUTABILITY_CHECK);
	}

	@Override
	protected int getExtensionLength() {
		return 0;
	}

	@Override
	protected void writeExtensionTo(DatagramWriter writer) {
		// empty
	}

	/**
	 * Create extended master secret extension from extensions data bytes.
	 * 
	 * @param extensionDataReader extension data bytes
	 * @return created extended master secret extension
	 * @throws NullPointerException if extensionData is {@code null}
	 */
	public static ReturnRoutabilityCheckExtension fromExtensionDataReader(DatagramReader extensionDataReader)
			throws HandshakeException {
		if (extensionDataReader == null) {
			throw new NullPointerException("Return routability check must not be null!");
		}

		return INSTANCE;
	}
}
