/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
	X_509(0, true), OPEN_PGP(1, false), RAW_PUBLIC_KEY(2, true);

	private final int code;
	private final boolean isSupported;
	
	private CertificateType(int code, boolean isSupported) {
		this.code = code;
		this.isSupported = isSupported;
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

	public final int getCode() {
		return code;
	}

	public final boolean isSupported() {
		return isSupported;
	}
}
