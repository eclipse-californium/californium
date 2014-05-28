/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.scandium.dtls.HelloExtensions.ExtensionType;
import org.eclipse.californium.scandium.util.DatagramReader;


public class ClientCertificateTypeExtension extends CertificateTypeExtension {
	
	// Constructors ///////////////////////////////////////////////////
	
	/**
	 * Constructs an empty certificate type extension. If it is client-sided
	 * there is a list of supported certificate type (ordered by preference);
	 * server-side only 1 certificate type is chosen.
	 * 
	 * @param isClient
	 *            whether this instance is considered the client.
	 */
	public ClientCertificateTypeExtension(boolean isClient) {
		super(ExtensionType.CLIENT_CERT_TYPE, isClient);
	}
	
	/**
	 * Constructs a certificate type extension with a list of supported
	 * certificate types. The server only chooses 1 certificate type.
	 * 
	 * @param certificateTypes
	 *            the list of supported certificate types.
	 * @param isClient
	 *            whether this instance is considered the client.
	 */
	public ClientCertificateTypeExtension(boolean isClient, List<CertificateType> certificateTypes) {
		super(ExtensionType.CLIENT_CERT_TYPE, isClient, certificateTypes);
	}

	// Methods ////////////////////////////////////////////////////////

	public String toString() {
		StringBuilder sb = new StringBuilder(super.toString());

		for (CertificateType type : certificateTypes) {
			sb.append("\t\t\t\tClient certificate type: " + type.toString() + "\n");
		}

		return sb.toString();
	};
	
	public static HelloExtension fromByteArray(byte[] byteArray) {
		DatagramReader reader = new DatagramReader(byteArray);
		
		List<CertificateType> certificateTypes = new ArrayList<CertificateType>();
		
		// the client's extension needs at least 2 bytes, while the server's is exactly 1 byte long
		boolean isClientExtension = true;
		if (byteArray.length > 1) {
			int length = reader.read(LIST_FIELD_LENGTH_BITS);
			for (int i = 0; i < length; i++) {
				certificateTypes.add(CertificateType.getTypeFromCode(reader.read(EXTENSION_TYPE_BITS)));
			}
		} else {
			certificateTypes.add(CertificateType.getTypeFromCode(reader.read(EXTENSION_TYPE_BITS)));
			isClientExtension = false;
		}

		return new ClientCertificateTypeExtension(isClientExtension, certificateTypes);
	}
}
