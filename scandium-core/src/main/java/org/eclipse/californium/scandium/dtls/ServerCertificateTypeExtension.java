/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - small improvements to serialization
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.util.List;

import org.eclipse.californium.elements.util.DatagramReader;

public class ServerCertificateTypeExtension extends CertificateTypeExtension {

	private ServerCertificateTypeExtension(DatagramReader extensionDataReader) {
		super(ExtensionType.SERVER_CERT_TYPE, extensionDataReader);
	}

	/**
	 * Constructs a client-side certificate type extension with a list of
	 * supported certificate types.
	 * 
	 * @param certificateTypes the list of supported certificate types.
	 */
	public ServerCertificateTypeExtension(List<CertificateType> certificateTypes) {
		super(ExtensionType.SERVER_CERT_TYPE, certificateTypes);
	}

	/**
	 * Constructs a server-side certificate type extension with the supported
	 * certificate type.
	 * 
	 * @param certificateType the supported certificate type.
	 */
	public ServerCertificateTypeExtension(CertificateType certificateType) {
		super(ExtensionType.SERVER_CERT_TYPE, certificateType);
	}

	@Override
	public String toString(int indent) {
		return super.toString(indent, "Server");
	}

	/**
	 * Constructs a server certificate type extension with a list of supported
	 * certificate types, or a selected certificate type chosen by the server.
	 * 
	 * @param extensionDataReader the list of supported certificate types or the
	 *            selected certificate type encoded in bytes.
	 * @return the created certificate type extension
	 * @throws NullPointerException if extension data is {@code null}
	 * @throws IllegalArgumentException if extension data is empty
	 */
	public static ServerCertificateTypeExtension fromExtensionDataReader(DatagramReader extensionDataReader) {
		return new ServerCertificateTypeExtension(extensionDataReader);
	}
}
