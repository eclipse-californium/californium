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

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.HelloExtension.ExtensionType;

/**
 * A container for one or more {@link HelloExtension}s.
 */
public final class HelloExtensions {

	public static final int OVERALL_LENGTH_BITS = 16;

	/** The list of extensions. */
	private final List<HelloExtension> extensions = new ArrayList<HelloExtension>();

	public HelloExtensions() {
	}

	/**
	 * Checks if this container actually holds any extensions.
	 * 
	 * @return {@code true}, if there are no extensions
	 */
	boolean isEmpty() {
		return this.extensions.isEmpty();
	}

	/**
	 * Calculate the lengths of the whole extension fragment.
	 * 
	 * Includes the two bytes to encode the {@link #getExtensionsLength()}
	 * itself.
	 * <a href="https://tools.ietf.org/html/rfc5246#section-7.4.1.2" target=
	 * "_blank">RFC5246, 7.4.1.2</a>
	 * 
	 * <pre>
	 * select (extensions_present) {
	 * case false:
	 * 		struct {};
	 * case true:
	 * 		Extension extensions&lt;0..2^16-1&gt;;
	 * };
	 * </pre>
	 * 
	 * @return the length of the whole extension fragment. {@code 0}, if no
	 *         extensions are used.
	 * @since 3.0 (added two bytes to encode the length itself)
	 */
	public int getLength() {
		if (extensions.isEmpty()) {
			return 0;
		} else {
			return getExtensionsLength() + (OVERALL_LENGTH_BITS / Byte.SIZE);
		}
	}

	/**
	 * Calculate the length of all extensions.
	 * 
	 * @return the length of all extensions.
	 * @since 3.0
	 */
	public int getExtensionsLength() {
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
	 * @param type the type of extension or replacement type
	 * @return the extension, or {@code null}, if no extension of the given type
	 *         nor replacement type is present
	 * @throws NullPointerException if type is {@code null}
	 * @since 3.0 (added NullPointerException and replacement type)
	 */
	@SuppressWarnings("unchecked")
	public <T extends HelloExtension> T getExtension(ExtensionType type) {
		if (type == null) {
			throw new NullPointerException("Extension type must not be null!");
		}
		HelloExtension replacement = null;
		for (HelloExtension ext : extensions) {
			if (type.equals(ext.getType())) {
				return (T) ext;
			} else if (type.equals(ext.getType().getReplacementType())) {
				replacement = ext;
			}
		}
		return (T) replacement;
	}

	/**
	 * Get list of extensions.
	 * 
	 * @return (unmodifiable) list of extensions
	 */
	public List<HelloExtension> getExtensions() {
		return Collections.unmodifiableList(extensions);
	}

	/**
	 * Gets the textual presentation of this message.
	 * 
	 * @param indent line indentation
	 * @return textual presentation
	 * @since 3.0
	 */
	public String toString(int indent) {
		StringBuilder sb = new StringBuilder();
		String indentation = StringUtil.indentation(indent);
		sb.append(indentation).append("Extensions Length: ").append(getExtensionsLength()).append(" bytes")
				.append(StringUtil.lineSeparator());
		for (HelloExtension ext : extensions) {
			sb.append(ext.toString(indent + 1));
		}
		return sb.toString();
	}

	@Override
	public String toString() {
		return toString(0);
	}

	/**
	 * Write extensions.
	 * 
	 * @param writer writer to write extensions to.
	 * @since 3.0
	 */
	public void writeTo(DatagramWriter writer) {
		if (!extensions.isEmpty()) {
			writer.write(getExtensionsLength(), OVERALL_LENGTH_BITS);
			for (HelloExtension extension : extensions) {
				extension.writeTo(writer);
			}
		}
	}

	/**
	 * Read extensions from reader.
	 * 
	 * @param reader the serialized extensions
	 * @throws HandshakeException if the (supported) extension could not be
	 *             de-serialized, e.g. due to erroneous encoding etc. Or a
	 *             extension type occurs more than once.
	 */
	public void readFrom(DatagramReader reader) throws HandshakeException {
		if (reader.bytesAvailable()) {
			try {
				int length = reader.read(OVERALL_LENGTH_BITS);
				DatagramReader rangeReader = reader.createRangeReader(length);
				while (rangeReader.bytesAvailable()) {
					HelloExtension extension = HelloExtension.readFrom(rangeReader);
					if (extension != null) {
						if (getExtension(extension.getType()) == null) {
							addExtension(extension);
						} else {
							throw new HandshakeException(
									"Hello message contains extension " + extension.getType() + " more than once!",
									new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR));
						}
					}
				}
			} catch (IllegalArgumentException ex) {
				throw new HandshakeException("Hello message contained malformed extensions, " + ex.getMessage(),
						new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR));
			}
		}
	}

	/**
	 * Create and read extensions.
	 * 
	 * @param reader the serialized extension
	 * @return create extensions
	 * @throws HandshakeException if the (supported) extension could not be
	 *             de-serialized, e.g. due to erroneous encoding etc. Or a
	 *             extension type occurs more than once.
	 */
	public static HelloExtensions fromReader(DatagramReader reader) throws HandshakeException {
		HelloExtensions extensions = new HelloExtensions();
		extensions.readFrom(reader);
		return extensions;
	}

}
