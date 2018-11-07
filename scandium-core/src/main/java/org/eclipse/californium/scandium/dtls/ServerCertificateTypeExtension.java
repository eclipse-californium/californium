/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - small improvements to serialization
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.util.List;

import org.eclipse.californium.elements.util.StringUtil;

public class ServerCertificateTypeExtension extends CertificateTypeExtension {

	// Constructors ///////////////////////////////////////////////////
	
	private ServerCertificateTypeExtension(byte[] extensionData) {
		super(ExtensionType.SERVER_CERT_TYPE, extensionData);
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

	// Methods ////////////////////////////////////////////////////////

	public String toString() {
		StringBuilder sb = new StringBuilder(super.toString());

		for (CertificateType type : getCertificateTypes()) {
			sb.append("\t\t\t\tServer certificate type: ").append(type).append(StringUtil.lineSeparator());
		}

		return sb.toString();
	}

	/**
	 * Constructs a server certificate type extension with a list of supported
	 * certificate types, or a selected certificate type chosen by the server.
	 * 
	 * @param extensionData the list of supported certificate types or the
	 *            selected certificate type encoded in bytes.
	 * @return the created certificate type extension
	 * @throws NullPointerException if extension data is {@code null}
	 * @throws IllegalArgumentException if extension data is empty
	 */
	public static ServerCertificateTypeExtension fromExtensionData(byte[] extensionData) {
		return new ServerCertificateTypeExtension(extensionData);
	}
}
