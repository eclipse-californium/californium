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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - small improvements
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography.SupportedGroup;


/**
 * The supported elliptic curves extension.
 * 
 * For details see <a href="http://tools.ietf.org/html/rfc4492#section-5.1.1">
 * RFC 4492</a>.
 */
public final class SupportedEllipticCurvesExtension extends HelloExtension {

	// DTLS-specific constants ////////////////////////////////////////

	private static final int LIST_LENGTH_BITS = 16;

	private static final int CURVE_BITS = 16;
	
	// Members ////////////////////////////////////////////////////////
	
	/** The list holding the supported named curves IDs */
	private final List<Integer> supportedGroups;
	
	// Constructor ////////////////////////////////////////////////////

	/**
	 * 
	 * @param supportedGroupIds
	 *            the list of supported named curves.
	 */
	public SupportedEllipticCurvesExtension(List<Integer> supportedGroupIds) {
		super(ExtensionType.ELLIPTIC_CURVES);
		this.supportedGroups = new ArrayList<Integer>(supportedGroupIds);
	}

	/**
	 * Creates an instance using the IDs of a given set of supported groups.
	 * 
	 * @param supportedGroups
	 *            the supported groups
	 */
	public SupportedEllipticCurvesExtension(SupportedGroup[] supportedGroups) {
		super(ExtensionType.ELLIPTIC_CURVES);
		this.supportedGroups = new ArrayList<Integer>();
		for (SupportedGroup group : supportedGroups) {
			this.supportedGroups.add(group.getId());
		}
	}
	
	// Serialization //////////////////////////////////////////////////

	@Override
	protected void addExtensionData(DatagramWriter writer) {
		int listLength = supportedGroups.size() * 2;
		writer.write(listLength + 2, LENGTH_BITS);
		writer.write(listLength, LIST_LENGTH_BITS);

		for (Integer groupId : supportedGroups) {
			writer.write(groupId, CURVE_BITS);
		}
	}

	public static HelloExtension fromExtensionData(byte[] extensionData) {
		DatagramReader reader = new DatagramReader(extensionData);

		int listLength = reader.read(LIST_LENGTH_BITS);

		List<Integer> groupIds = new ArrayList<Integer>();
		while (listLength > 0) {
			int id = reader.read(CURVE_BITS);
			groupIds.add(id);

			listLength -= 2;
		}

		return new SupportedEllipticCurvesExtension(groupIds);
	}
	
	// Methods ////////////////////////////////////////////////////////
	
	@Override
	public int getLength() {
		// fixed: type (2 bytes), length (2 bytes), list length (2 bytes)
		// variable: number of named curves * 2 (2 bytes for each curve)
		return 6 + (supportedGroups.size() * 2);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(super.toString());
		sb.append("\t\t\t\tLength: ").append(getLength() - 4);
		sb.append(System.lineSeparator()).append("\t\t\t\tElliptic Curves Length: ").append(getLength() - 6);
		sb.append(System.lineSeparator()).append("\t\t\t\tElliptic Curves (").append(supportedGroups.size()).append(" curves):");

		for (Integer curveId : supportedGroups) {
			SupportedGroup group = SupportedGroup.fromId(curveId);
			sb.append(System.lineSeparator()).append("\t\t\t\t\tElliptic Curve: ");
			if (group != null) {
				sb.append(group.name());
			} else {
				sb.append("unknown");
			}
			sb.append(" (").append(curveId).append(")");
		}

		return sb.toString();
	}

	public List<Integer> getSupportedGroupIds() {
		return Collections.unmodifiableList(supportedGroups);
	}

}
