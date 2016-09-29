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
 *    Kai Hudalla - fixes & improvements
 *    Kai Hudalla (Bosch Software Innovations GmbH) - getter for retrieving extension
 *                                                    of a particular type
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use peer address when parsing
 *                                                    from byte array
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.HelloExtension.ExtensionType;


/**
 * A container for one or more {@link HelloExtension}s.
 */
public final class HelloExtensions {
	// Logging ////////////////////////////////////////////////////////

	private static final Logger LOGGER = Logger.getLogger(HelloExtensions.class.getCanonicalName());

	// DTLS-specific constants ////////////////////////////////////////

	public static final int LENGTH_BITS = 16;

	// Members ////////////////////////////////////////////////////////

	/** The list of extensions. */
	private final List<HelloExtension> extensions= new ArrayList<HelloExtension>();

	// Constructors ///////////////////////////////////////////////////

	public HelloExtensions() {
	}

	public HelloExtensions(List<HelloExtension> extensions) {
		this.extensions.addAll(extensions);
	}

	// Methods ////////////////////////////////////////////////////////

	/**
	 * Checks if this container actually holds any extensions.
	 * 
	 * @return <code>true</code> if there are any extensions
	 */
	boolean isEmpty() {
		return this.extensions.isEmpty();
	}

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
		if (extension != null) {
			this.extensions.add(extension);
		}
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("\t\tExtensions Length: ").append(getLength());
		for (HelloExtension ext : extensions) {
			sb.append(System.lineSeparator()).append(ext);
		}
		return sb.toString();
	}

	// Serialization //////////////////////////////////////////////////

	public byte[] toByteArray() {
		if (extensions.isEmpty()) {
			return new byte[]{};
		} else {
			DatagramWriter writer = new DatagramWriter();

			writer.write(getLength(), LENGTH_BITS);
			for (HelloExtension extension : extensions) {
				writer.writeBytes(extension.toByteArray());
			}

			return writer.toByteArray();
		}
	}

	public static HelloExtensions fromByteArray(byte[] byteArray, InetSocketAddress peerAddress) throws HandshakeException {
		DatagramReader reader = new DatagramReader(byteArray);
		List<HelloExtension> extensions = new ArrayList<HelloExtension>();

		int length = reader.read(LENGTH_BITS);

		while (length > 0) {
			int typeId = reader.read(HelloExtension.TYPE_BITS);
			int extensionLength = reader.read(HelloExtension.LENGTH_BITS);
			byte[] extensionBytes = reader.readBytes(extensionLength);
			HelloExtension extension = HelloExtension.fromByteArray(typeId, extensionBytes, peerAddress);

			if (extension != null) {
				extensions.add(extension);
			} else {
				LOGGER.log(
						Level.FINER,
						"Peer included an unknown extension type code [{0}] in its Hello message",
						typeId);
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
					new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR, peerAddress));
		} else {
			return new HelloExtensions(extensions);
		}
	}

	/**
	 * Gets a hello extension of a particular type.
	 * 
	 * @param type the type of extension
	 * @return the extension or <code>null</code> if no extension
	 *     of the given type is present
	 */
	final HelloExtension getExtension(ExtensionType type) {
		if (type != null) {
			for (HelloExtension ext : extensions) {
				if (type.equals(ext.getType())) {
					return ext;
				}
			}
		}
		return null;
	}

	public List<HelloExtension> getExtensions() {
		return Collections.unmodifiableList(extensions);
	}
}
