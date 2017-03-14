/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;

/**
 * An object representation of the <em>MaxFragmentLength</em> extension
 * for the <em>Transport Level Security</em> protocol.
 * <p>
 * Instances of this class can be serialized to and deserialized from the
 * <em>MaxFragmentLength</em> data structure defined in <a
 * href="http://tools.ietf.org/html/rfc6066#section-4">RFC 6066, Section 4</a>.
 */
public class MaxFragmentLengthExtension extends HelloExtension {

	public static final int CODE_BITS = 8;
	private final Length fragmentLength;

	public MaxFragmentLengthExtension(int fragmentLengthCode) {
		this(Length.fromCode(fragmentLengthCode));
	}

	public MaxFragmentLengthExtension(Length fragmentLength) {
		super(ExtensionType.MAX_FRAGMENT_LENGTH);
		if (fragmentLength == null) {
			throw new NullPointerException("Length must not be null");
		}
		this.fragmentLength = fragmentLength;
	}

	public Length getFragmentLength() {
		return fragmentLength;
	}

	@Override
	public int getLength() {
		// fixed: 2 byte (type ID) + 2 byte (length of extension data) + 1 byte (extension data)
		return 5;
	}

	/**
	 * Creates an instance from a <em>MaxFragmentLength</em> structure as defined
	 * in <a href="http://tools.ietf.org/html/rfc6066#section-4">RFC 6066, Section 4</a>.
	 * 
	 * @param extensionData the extension data struct containing the length code
	 * @param peerAddress the IP address and port of the peer that sent the extension
	 * @return the extension object
	 * @throws HandshakeException if the extension data contains an unknown code
	 */
	static final MaxFragmentLengthExtension fromExtensionData(byte[] extensionData,
			InetSocketAddress peerAddress) throws HandshakeException {
		DatagramReader reader = new DatagramReader(extensionData);
		int code = reader.read(CODE_BITS);
		Length length = Length.fromCode(code);
		if (length != null) {
			return new MaxFragmentLengthExtension(length);
		} else {
			throw new HandshakeException(
					String.format(
							"Peer uses unknown code [%d] in %s extension",
							code, ExtensionType.MAX_FRAGMENT_LENGTH.name()),
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER,
							peerAddress));
		}
	}

	@Override
	protected void addExtensionData(DatagramWriter writer) {
		writer.write(1, LENGTH_BITS);
		writer.write(fragmentLength.code, CODE_BITS);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(super.toString());
		sb.append("\t\t\t\tCode: ").append(fragmentLength.code()).append(" (")
			.append(fragmentLength.length()).append(" bytes)");
		return sb.toString();
	}

	/**
	 * The codes representing the lengths that can be negotiated using the
	 * <em>Max Fragment Length</em> Hello extension.
	 */
	public enum Length {
		BYTES_512(1, 512), BYTES_1024(2, 1024), BYTES_2048(3, 2048), BYTES_4096(4, 4096);

		private int code;
		private int length;
		
		private Length(int code, int length) {
			this.code = code;
			this.length = length;
		}

		public int code() {
			return code;
		}

		/**
		 * Gets the length in bytes this code represents.
		 * 
		 * @return the length
		 */
		public int length() {
			return length;
		}

		/**
		 * Creates an instance from its code.
		 * 
		 * @param code the code
		 * @return the instance or <code>null</code> if the given code is unknown
		 */
		public static Length fromCode(int code) {
			switch(code) {
			case 1:
				return BYTES_512;
			case 2:
				return BYTES_1024;
			case 3:
				return BYTES_2048;
			case 4:
				return BYTES_4096;
			default:
				return null;
			}
		}
	}
}
