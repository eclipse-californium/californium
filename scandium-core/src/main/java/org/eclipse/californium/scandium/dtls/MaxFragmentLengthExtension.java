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

import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;

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
	
	public MaxFragmentLengthExtension(Length fragmentLength) {
		super(ExtensionType.MAX_FRAGMENT_LENGTH);
		if (fragmentLength == null) {
			throw new NullPointerException("Length must not be null");
		}
		this.fragmentLength = fragmentLength;
	}

	@Override
	public int getLength() {
		// TODO Auto-generated method stub
		return 0;
	}

	static final MaxFragmentLengthExtension fromExtensionData(byte[] extensionData) {
		DatagramReader reader = new DatagramReader(extensionData);
		Length length = Length.fromCode(reader.read(CODE_BITS));
		if (length != null) {
			return new MaxFragmentLengthExtension(length);
		} else {
			return null;
		}
	}

	@Override
	protected void addExtensionData(DatagramWriter writer) {
		writer.write(fragmentLength.code, CODE_BITS);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(super.toString());
		sb.append("\t\t\t\tCode: ").append(fragmentLength.code()).append("\n");
		sb.append("\t\t\t\tMax. Fragment Length: ").append(fragmentLength.length());
		return sb.toString();
	}

	enum Length {
		BYTES_512(1, 512), BYTES_1024(2, 1024), BYTES_2048(3, 2048), BYTES_4096(4, 4096);

		private int code;
		private int length;
		
		private Length(int code, int length) {
			this.code = code;
			this.length = length;
		}

		int code() {
			return code;
		}

		int length() {
			return length;
		}

		static Length fromCode(int code) {
			for (Length length : values()) {
				if (length.code() == code) {
					return length;
				}
			}
			return null;
		}
	}
}
