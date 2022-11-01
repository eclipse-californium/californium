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
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;

/**
 * Extended master secret extension.
 * <p>
 * See <a href="https://tools.ietf.org/html/rfc7627" target="_blank">RFC 7627</a> and
 * {@link ExtendedMasterSecretMode}for additional details.
 * 
 * @since 3.0
 */
public final class ExtendedMasterSecretExtension extends HelloExtension {

	public static ExtendedMasterSecretExtension INSTANCE = new ExtendedMasterSecretExtension();

	/**
	 * Create extended master secret extension.
	 */
	private ExtendedMasterSecretExtension() {
		super(ExtensionType.EXTENDED_MASTER_SECRET);
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
	public static ExtendedMasterSecretExtension fromExtensionDataReader(DatagramReader extensionDataReader) {
		if (extensionDataReader == null) {
			throw new NullPointerException("extended master secret must not be null!");
		}
		return INSTANCE;
	}
}
