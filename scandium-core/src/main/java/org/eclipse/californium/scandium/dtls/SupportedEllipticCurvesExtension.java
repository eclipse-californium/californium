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
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;


/**
 * The supported elliptic curves extension.
 * 
 * According <a href= "https://tools.ietf.org/html/rfc8422#section-5.1.1">RFC
 * 8422, 5.1.1. Supported Elliptic Curves Extension</a> only "named curves" are
 * valid, the "prime" and "char2" curve descriptions are deprecated.
 */
@NoPublicAPI
public final class SupportedEllipticCurvesExtension extends HelloExtension {

	// DTLS-specific constants ////////////////////////////////////////

	private static final int LIST_LENGTH_BITS = 16;

	private static final int CURVE_BITS = 16;
	
	// Members ////////////////////////////////////////////////////////
	
	/** The list holding the supported groups (named curves) */
	private final List<SupportedGroup> supportedGroups;

	// Constructor ////////////////////////////////////////////////////

	/**
	 * Create supported elliptic curves extension.
	 * 
	 * @param supportedGroups
	 *            the list of supported groups (named curves).
	 * 
	 * @since 2.3
	 */
	public SupportedEllipticCurvesExtension(List<SupportedGroup> supportedGroups) {
		super(ExtensionType.ELLIPTIC_CURVES);
		this.supportedGroups = supportedGroups;
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	protected void addExtensionData(DatagramWriter writer) {
		int listLength = supportedGroups.size() * (CURVE_BITS / Byte.SIZE);
		writer.write(listLength + (LIST_LENGTH_BITS / Byte.SIZE), LENGTH_BITS);
		writer.write(listLength, LIST_LENGTH_BITS);

		for (SupportedGroup group : supportedGroups) {
			writer.write(group.getId(), CURVE_BITS);
		}
	}

	public static HelloExtension fromExtensionDataReader(DatagramReader extensionDataReader) {

		List<SupportedGroup> groups = new ArrayList<>();
		int listLength = extensionDataReader.read(LIST_LENGTH_BITS);
		DatagramReader rangeReader = extensionDataReader.createRangeReader(listLength);
		while (rangeReader.bytesAvailable()) {
			int id = rangeReader.read(CURVE_BITS);
			SupportedGroup group = SupportedGroup.fromId(id);
			if (group != null) {
				groups.add(group);
			}
		}

		return new SupportedEllipticCurvesExtension(Collections.unmodifiableList(groups));
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public int getLength() {
		// fixed: type (2 bytes), length (2 bytes), list length (2 bytes)
		// variable: number of named curves * 2 (2 bytes for each curve)
		return 6 + (supportedGroups.size() * (CURVE_BITS / Byte.SIZE));
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(super.toString());
		sb.append("\t\t\t\tLength: ").append(getLength() - 4);
		sb.append(StringUtil.lineSeparator()).append("\t\t\t\tElliptic Curves Length: ").append(getLength() - 6);
		sb.append(StringUtil.lineSeparator()).append("\t\t\t\tElliptic Curves (").append(supportedGroups.size()).append(" curves):");

		for (SupportedGroup group : supportedGroups) {
			sb.append(StringUtil.lineSeparator()).append("\t\t\t\t\tElliptic Curve: ");
			sb.append(group.name()).append(" (").append(group.getId()).append(")");
		}

		return sb.toString();
	}

	/**
	 * Get list of contained supported (and usable) groups (curves).
	 * 
	 * @return list of supported groups.
	 */
	public List<SupportedGroup> getSupportedGroups() {
		return supportedGroups;
	}

}
