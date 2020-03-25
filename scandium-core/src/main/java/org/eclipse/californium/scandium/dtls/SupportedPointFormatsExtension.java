/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - small improvements
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.elements.util.StringUtil;


/**
 * The supported point formats extension.
 * 
 * According <a href= "https://tools.ietf.org/html/rfc8422#section-5.1.1">RFC
 * 8422, 5.1.1. Supported Elliptic Curves Extension</a> only only "UNCOMPRESSED"
 * as point format is valid, the other formats have been deprecated.
 */
@NoPublicAPI
public class SupportedPointFormatsExtension extends HelloExtension {

	// DTLS-specific constants ////////////////////////////////////////

	private static final int LIST_LENGTH_BITS = 8;

	private static final int POINT_FORMAT_BITS = 8;

	private static final List<ECPointFormat> EC_POINT_FORMATS = Collections.singletonList(ECPointFormat.UNCOMPRESSED);

	/**
	 * Default ec point format extension.
	 * 
	 * @since 2.3
	 */
	public static final SupportedPointFormatsExtension DEFAULT_POINT_FORMATS_EXTENSION = new SupportedPointFormatsExtension(EC_POINT_FORMATS);

	// Members ////////////////////////////////////////////////////////

	/**
	 * Items in here are ordered according to the client's preferences (favorite
	 * choice first).
	 */
	List<ECPointFormat> ecPointFormatList;

	// Constructors ///////////////////////////////////////////////////

	private SupportedPointFormatsExtension(List<ECPointFormat> ecPointFormatList) {
		super(ExtensionType.EC_POINT_FORMATS);
		this.ecPointFormatList = ecPointFormatList;
	}

	// Methods ////////////////////////////////////////////////////////

	public boolean contains(ECPointFormat format) {
		return ecPointFormatList.contains(format);
	}

	@Override
	public int getLength() {
		// fixed: type (2 bytes), length (2 bytes), list length (1 byte)
		// variable: number of point formats
		return 5 + ecPointFormatList.size();
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(super.toString());
		sb.append("\t\t\t\tLength: ").append(getLength() - 4);
		sb.append(StringUtil.lineSeparator()).append("\t\t\t\tEC point formats length: ").append(getLength() - 5);
		sb.append(StringUtil.lineSeparator()).append("\t\t\t\tElliptic Curves Point Formats (").append(ecPointFormatList.size()).append("):");

		for (ECPointFormat format : ecPointFormatList) {
			sb.append(StringUtil.lineSeparator()).append("\t\t\t\t\tEC point format: ").append(format.toString());
		}

		return sb.toString();
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	protected void addExtensionData(DatagramWriter writer) {
		int listLength = ecPointFormatList.size();
		// list length + list length field (1 byte)
		writer.write(listLength + 1, LENGTH_BITS);
		writer.write(listLength, LIST_LENGTH_BITS);

		for (ECPointFormat format : ecPointFormatList) {
			writer.write(format.getId(), POINT_FORMAT_BITS);
		}
	}

	public static HelloExtension fromExtensionDataReader(DatagramReader extensionDataReader) {

		List<ECPointFormat> ecPointFormatList = new ArrayList<ECPointFormat>();
		int listLength = extensionDataReader.read(LIST_LENGTH_BITS);
		DatagramReader rangeReader = extensionDataReader.createRangeReader(listLength);
		while (rangeReader.bytesAvailable()) {
			ECPointFormat format = ECPointFormat.getECPointFormatById(rangeReader.read(POINT_FORMAT_BITS));
			if (format != null) {
				ecPointFormatList.add(format);
			}
		}
		if (ecPointFormatList.size() == 1 && ecPointFormatList.contains(ECPointFormat.UNCOMPRESSED)) {
			return DEFAULT_POINT_FORMATS_EXTENSION;
		} else {
			return new SupportedPointFormatsExtension(ecPointFormatList);
		}
	}

	// EC point format Enum ///////////////////////////////////////////

	/**
	 * See <a href="http://tools.ietf.org/html/rfc4492#section-5.1.2">RFC 4492,
	 * 5.1.2. Supported Point Formats Extension</a>.
	 */
	public enum ECPointFormat {
		UNCOMPRESSED(0), ANSIX962_COMPRESSED_PRIME(1), ANSIX962_COMPRESSED_CHAR2(2);

		private int id;

		private ECPointFormat(int id) {
			this.id = id;
		}

		public int getId() {
			return id;
		}

		@Override
		public String toString() {
			switch (id) {
			case 0:
				return "uncompressed (" + id + ")";
			case 1:
				return "ansiX962_compressed_prime (" + id + ")";
			case 2:
				return "ansiX962_compressed_char2 (" + id + ")";
			default:
				return "";
			}
		}

		public static ECPointFormat getECPointFormatById(int id) {
			switch (id) {
			case 0:
				return ECPointFormat.UNCOMPRESSED;
			case 1:
				return ECPointFormat.ANSIX962_COMPRESSED_PRIME;
			case 2:
				return ECPointFormat.ANSIX962_COMPRESSED_CHAR2;

			default:
				return null;
			}
		}

	}

}
