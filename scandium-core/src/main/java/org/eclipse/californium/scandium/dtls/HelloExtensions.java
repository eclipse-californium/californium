/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla - fixes & improvements
 *    Kai Hudalla (Bosch Software Innovations GmbH) - getter for retrieving extension
 *                                                    of a particular type
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use peer address when parsing
 *                                                    from byte array
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.HelloExtension.ExtensionType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A container for one or more {@link HelloExtension}s.
 */
public final class HelloExtensions {
	// Logging ////////////////////////////////////////////////////////

	private static final Logger LOGGER = LoggerFactory.getLogger(HelloExtensions.class);

	// DTLS-specific constants ////////////////////////////////////////

	public static final int LENGTH_BITS = 16;

	// Members ////////////////////////////////////////////////////////

	/** The list of extensions. */
	private final List<HelloExtension> extensions= new ArrayList<HelloExtension>();

	// Constructors ///////////////////////////////////////////////////

	public HelloExtensions() {
	}

	// Methods ////////////////////////////////////////////////////////

	/**
	 * Checks if this container actually holds any extensions.
	 * 
	 * @return <code>true</code> if there are no extensions
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

	/**
	 * Add hello extension.
	 * 
	 * @param extension hello extension to add
	 * @throws IllegalArgumentException if extension of that type was already
	 *             added.
	 */
	public void addExtension(HelloExtension extension) {
		if (extension != null) {
			if (getExtension(extension.getType()) == null) {
				this.extensions.add(extension);
			} else {
				throw new IllegalArgumentException(
						"Hello Extension of type " + extension.getType() + " already added!");
			}
		}
	}

	/**
	 * Gets a hello extension of a particular type.
	 * 
	 * @param <T> java-type of extension
	 * @param type the type of extension
	 * @return the extension, or {@code null}, if no extension of the given type
	 *         is present
	 */
	@SuppressWarnings("unchecked")
	public <T extends HelloExtension> T getExtension(ExtensionType type) {
		if (type != null) {
			for (HelloExtension ext : extensions) {
				if (type.equals(ext.getType())) {
					return (T) ext;
				}
			}
		}
		return null;
	}

	public List<HelloExtension> getExtensions() {
		return Collections.unmodifiableList(extensions);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("\t\tExtensions Length: ").append(getLength());
		for (HelloExtension ext : extensions) {
			sb.append(StringUtil.lineSeparator()).append(ext);
		}
		return sb.toString();
	}

	// Serialization //////////////////////////////////////////////////

	public byte[] toByteArray() {
		if (extensions.isEmpty()) {
			return Bytes.EMPTY;
		} else {
			DatagramWriter writer = new DatagramWriter();

			writer.write(getLength(), LENGTH_BITS);
			for (HelloExtension extension : extensions) {
				writer.writeBytes(extension.toByteArray());
			}

			return writer.toByteArray();
		}
	}

	public static HelloExtensions fromReader(DatagramReader reader) throws HandshakeException {
		try {
			HelloExtensions extensions = new HelloExtensions();
			if (reader.bytesAvailable()) {
				int length = reader.read(LENGTH_BITS);
				DatagramReader rangeReader = reader.createRangeReader(length);
				while (rangeReader.bytesAvailable()) {
					int typeId = rangeReader.read(HelloExtension.TYPE_BITS);
					int extensionLength = rangeReader.read(HelloExtension.LENGTH_BITS);
					DatagramReader extensionDataReader = rangeReader.createRangeReader(extensionLength);
					HelloExtension extension = HelloExtension.fromExtensionDataReader(typeId, extensionDataReader);
					if (extensionDataReader.bytesAvailable()) {
						byte[] bytesLeft = extensionDataReader.readBytesLeft();
						throw new HandshakeException(String.format(
								"Too many bytes, %d left, hello extension not completely parsed! hello extension type %d",
								bytesLeft.length, typeId),
								new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR));
					}
					if (extension != null) {
						if (extensions.getExtension(extension.getType()) == null) {
							extensions.addExtension(extension);
						} else {
							throw new HandshakeException(
									"Hello message contains extension " + extension.getType() + " more than once!",
									new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR));
						}
					} else {
						LOGGER.debug("Peer included an unknown extension type code [{}] in its Hello message", typeId);
					}
				}
			}
			return extensions;
		} catch (IllegalArgumentException ex) {
			throw new HandshakeException("Hello message contained malformed extensions, " + ex.getMessage(),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR));
		}
	}

}
