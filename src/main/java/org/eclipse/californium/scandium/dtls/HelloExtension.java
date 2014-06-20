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

import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.HelloExtensions.ExtensionType;
import org.eclipse.californium.scandium.util.DatagramWriter;


/**
 * 
 * An abstract class representing the functionality for all possible defined
 * extensions. See <a
 * href="http://tools.ietf.org/html/rfc5246#section-7.4.1.4">RFC 5246</a> for
 * the extension format.
 */
public abstract class HelloExtension {

	// DTLS-specific constants ////////////////////////////////////////

	private static final int TYPE_BITS = 16;

	protected static final int LENGTH_BITS = 16;

	// Members ////////////////////////////////////////////////////////

	private ExtensionType type;

	// Constructors ///////////////////////////////////////////////////

	public HelloExtension(ExtensionType type) {
		this.type = type;
	}

	// Abstract methods ///////////////////////////////////////////////

	public abstract int getLength();

	// Serialization //////////////////////////////////////////////////

	public byte[] toByteArray() {
		DatagramWriter writer = new DatagramWriter();

		writer.write(type.getId(), TYPE_BITS);

		return writer.toByteArray();
	}
	
	public static HelloExtension fromByteArray(byte[] byteArray, ExtensionType type) throws HandshakeException {

		switch (type) {
		// the currently supported extensions, throws an exception if other extension type received
		case ELLIPTIC_CURVES:
			return SupportedEllipticCurvesExtension.fromByteArray(byteArray);
		case EC_POINT_FORMATS:
			return SupportedPointFormatsExtension.fromByteArray(byteArray);
		case CLIENT_CERT_TYPE:
			return ClientCertificateTypeExtension.fromByteArray(byteArray);
		case SERVER_CERT_TYPE:
			return ServerCertificateTypeExtension.fromByteArray(byteArray);

		default:
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.UNSUPPORTED_EXTENSION);
			throw new HandshakeException("Unsupported extension type received: " + type.toString(), alert);
		}

	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("\t\t\tExtension: " + type.toString() + " (" + type.getId() + ")\n");

		return sb.toString();
	}
}
