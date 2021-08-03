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
 * According <a href="https://tools.ietf.org/html/rfc8422#section-5.1.1" target=
 * "_blank">RFC 8422, 5.1.1. Supported Elliptic Curves Extension</a> only "named
 * curves" are valid, the "prime" and "char2" curve descriptions are deprecated.
 */
@NoPublicAPI
public final class SupportedEllipticCurvesExtension extends HelloExtension {

	private static final int LIST_LENGTH_BITS = 16;

	private static final int CURVE_BITS = 16;

	/** The list holding the supported groups (named curves) */
	private final List<SupportedGroup> supportedGroups;

	/**
	 * Create supported elliptic curves extension.
	 * 
	 * @param supportedGroups the list of supported groups (named curves).
	 * 
	 * @since 2.3
	 */
	public SupportedEllipticCurvesExtension(List<SupportedGroup> supportedGroups) {
		super(ExtensionType.ELLIPTIC_CURVES);
		this.supportedGroups = supportedGroups;
	}

	/**
	 * Get list of contained supported (and usable) groups (curves).
	 * 
	 * @return list of supported groups.
	 */
	public List<SupportedGroup> getSupportedGroups() {
		return supportedGroups;
	}

	@Override
	public String toString(int indent) {
		StringBuilder sb = new StringBuilder(super.toString(indent));
		String indentation = StringUtil.indentation(indent + 1);
		String indentation2 = StringUtil.indentation(indent + 2);
		sb.append(indentation).append("Elliptic Curves (").append(supportedGroups.size()).append(" curves):")
				.append(StringUtil.lineSeparator());
		for (SupportedGroup group : supportedGroups) {
			sb.append(indentation2).append("Elliptic Curve: ").append(group.name()).append(" (").append(group.getId())
					.append(")").append(StringUtil.lineSeparator());
		}

		return sb.toString();
	}

	@Override
	protected int getExtensionLength() {
		// fixed: list length (2 bytes)
		// variable: number of named curves * 2 (2 bytes for each curve)
		return (LIST_LENGTH_BITS / Byte.SIZE) + (supportedGroups.size() * (CURVE_BITS / Byte.SIZE));
	}

	@Override
	protected void writeExtensionTo(DatagramWriter writer) {
		int listLength = supportedGroups.size() * (CURVE_BITS / Byte.SIZE);
		writer.write(listLength, LIST_LENGTH_BITS);

		for (SupportedGroup group : supportedGroups) {
			writer.write(group.getId(), CURVE_BITS);
		}
	}

	public static SupportedEllipticCurvesExtension fromExtensionDataReader(DatagramReader extensionDataReader) {

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

}
