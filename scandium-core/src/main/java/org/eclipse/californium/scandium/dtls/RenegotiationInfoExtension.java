/*******************************************************************************
 * Copyright (c) 2022 Contributors to the Eclipse Foundation.
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;

/**
 * Renegotiation info extension.
 * <p>
 * Californium doesn't support renegotiation, but RFC5746 requests to update to
 * a minimal version.
 * 
 * See <a href="https://tools.ietf.org/html/rfc5746" target="_blank">RFC
 * 5746</a> for additional details.
 * 
 * @since 3.8
 */
public final class RenegotiationInfoExtension extends HelloExtension {

	public static RenegotiationInfoExtension INSTANCE = new RenegotiationInfoExtension();

	/**
	 * Create renegotiation info extension.
	 */
	private RenegotiationInfoExtension() {
		super(ExtensionType.RENEGOTIATION_INFO);
	}

	@Override
	protected int getExtensionLength() {
		return 1;
	}

	@Override
	protected void writeExtensionTo(DatagramWriter writer) {
		// renegotiation info length 0
		writer.writeByte((byte) 0);
	}

	/**
	 * Create renegotiation info extension from extensions data bytes.
	 * 
	 * @param extensionDataReader extension data bytes
	 * @return created renegotiation info extension
	 * @throws NullPointerException if extensionData is {@code null}
	 * @throws HandshakeException if renegotiation info is not empty
	 */
	public static RenegotiationInfoExtension fromExtensionDataReader(DatagramReader extensionDataReader)
			throws HandshakeException {
		if (extensionDataReader == null) {
			throw new NullPointerException("renegotiation info must not be null!");
		}
		if (extensionDataReader.readNextByte() != 0) {
			throw new HandshakeException("renegotiation info must be empty!",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER));
		}
		return INSTANCE;
	}
}
