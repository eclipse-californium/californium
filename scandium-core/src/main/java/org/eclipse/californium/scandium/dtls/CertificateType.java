/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 *                                      extracted from CertificateTypeExtension
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

/**
 * Certificate types as defined in the
 * <a href="http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml">IANA registry</a>.
 */
public enum CertificateType {
	// values as defined by IANA TLS Certificate Types registry
	X_509(0), OPEN_PGP(1), RAW_PUBLIC_KEY(2);

	private int code;

	private CertificateType(int code) {
		this.code = code;
	}
	
	public static CertificateType getTypeFromCode(int code) {
		switch (code) {
		case 0:
			return X_509;
		case 1:
			return OPEN_PGP;
		case 2:
			return RAW_PUBLIC_KEY;

		default:
			return null;
		}
	}

	int getCode() {
		return code;
	}
}
