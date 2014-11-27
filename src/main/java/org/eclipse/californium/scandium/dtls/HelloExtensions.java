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
 *    Kai Hudalla - fixes & improvements
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;


/**
 * Represents a structure to hold several {@link HelloExtension}.
 */
public class HelloExtensions {
	// Logging ////////////////////////////////////////////////////////

	private static final Logger LOGGER = Logger.getLogger(HelloExtensions.class.getCanonicalName());

	// DTLS-specific constants ////////////////////////////////////////

	public static final int LENGTH_BITS = 16;

	// Members ////////////////////////////////////////////////////////

	/** The list of extensions. */
	private List<HelloExtension> extensions;

	// Constructors ///////////////////////////////////////////////////

	public HelloExtensions() {
		this.extensions = new ArrayList<HelloExtension>();
	}

	public HelloExtensions(List<HelloExtension> extensions) {
		this.extensions = extensions;
	}

	// Methods ////////////////////////////////////////////////////////

	/**
	 * 
	 * @return the length of the whole extension fragment.
	 */
	public int getLength() {
		int length = 0;
		for (HelloExtension extension : extensions) {
			length += extension.getLength();
		}

		return length;
	}

	public void addExtension(HelloExtension extension) {
		this.extensions.add(extension);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("\t\tExtensions Length: " + getLength() + "\n");
		for (HelloExtension ext : extensions) {
			sb.append(ext.toString());
		}
		return sb.toString();
	}

	// Serialization //////////////////////////////////////////////////

	public byte[] toByteArray() {
		DatagramWriter writer = new DatagramWriter();

		writer.write(getLength(), LENGTH_BITS);
		for (HelloExtension extension : extensions) {
			writer.writeBytes(extension.toByteArray());
		}

		return writer.toByteArray();
	}

	public static HelloExtensions fromByteArray(byte[] byteArray) throws HandshakeException {
		DatagramReader reader = new DatagramReader(byteArray);
		List<HelloExtension> extensions = new ArrayList<HelloExtension>();

		int length = reader.read(LENGTH_BITS);

		while (length > 0) {
			int typeId = reader.read(HelloExtension.TYPE_BITS);
			int extensionLength = reader.read(HelloExtension.LENGTH_BITS);
			byte[] extensionBytes = reader.readBytes(extensionLength);
			HelloExtension extension = HelloExtension.fromByteArray(typeId, extensionBytes);
			
			if (extension != null) {
				extensions.add(extension);
			} else {
				LOGGER.log(Level.FINER,	String.format(
								"Client included an unknown extension type code in its Hello message [%d]",
								typeId));
			}
			// reduce by (type field length + length field length +
			// extension's length)
			length -= HelloExtension.TYPE_BITS / 8 + HelloExtension.LENGTH_BITS / 8
					+ extensionLength;

		}
		
		if (length < 0) {
			// the lengths of the extensions did not add up correctly
			// this is always FATAL as defined by the TLS spec (section 7.2.2)
			throw new HandshakeException(
					"Hello message contained malformed extensions",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR));
		} else {
			return new HelloExtensions(extensions);
		}
	}

	public List<HelloExtension> getExtensions() {
		// TODO: should we not better return an immutable copy? 
		return extensions;
	}
}
