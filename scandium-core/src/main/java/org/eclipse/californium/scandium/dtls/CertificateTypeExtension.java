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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - small improvements to serialization
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.util.ListUtils;


/**
 * This represents the Certificate Type Extension. See <a
 * href="http://tools.ietf.org/html/rfc7250">RFC 7250</a> for
 * details.
 */
public abstract class CertificateTypeExtension extends HelloExtension {

	private static final Logger LOG = LoggerFactory.getLogger(CertificateTypeExtension.class);
	
	// DTLS-specific constants ////////////////////////////////////////
	
	protected static final int LIST_FIELD_LENGTH_BITS = 8;
	
	protected static final int EXTENSION_TYPE_BITS = 8;

	// Members ////////////////////////////////////////////////////////

	/**
	 * Indicates whether this extension belongs to a client or a server. This
	 * has an impact upon the message format. See <a href=
	 * "http://tools.ietf.org/html/rfc7250#section-3">
	 *  CertificateTypeExtension</a> figure 4, definition.
	 */
	private final boolean isClientExtension;

	/**
	 * For the client: a list of certificate types the client supports, sorted
	 * by client preference.<br>
	 * For the server: the certificate selected by the server out of the
	 * client's list.
	 */
	private final List<CertificateType> certificateTypes;

	// Constructors ///////////////////////////////////////////////////
	/**
	 * Constructs a certificate type extension with a list of supported
	 * certificate types, or a selected certificate type chosen by the server.
	 * 
	 * @param type the type of the extension.
	 * @param extensionDataReader the list of supported certificate types or the
	 *            selected certificate type encoded in bytes.
	 * @throws NullPointerException if extension data is {@code null}
	 * @throws IllegalArgumentException if extension data is empty
	 */
	protected CertificateTypeExtension(ExtensionType type, DatagramReader extensionDataReader) {
		super(type);
		if (extensionDataReader == null) {
			throw new NullPointerException("extension data must not be null!");
		} else if (!extensionDataReader.bytesAvailable()) {
			throw new IllegalArgumentException("extension data must not be empty!");
		}
		// the selected certificate would be a single byte,
		// the supported list is longer
		isClientExtension = extensionDataReader.bitsLeft() > Byte.SIZE;
		List<CertificateType> types;
		if (isClientExtension) {
			// an extension containing a list of preferred certificate types
			// is at least 2 bytes long (1 byte length, 1 byte type)
			int length = extensionDataReader.read(LIST_FIELD_LENGTH_BITS);
			types = new ArrayList<>(length);
			DatagramReader rangeReader = extensionDataReader.createRangeReader(length);
			while (rangeReader.bytesAvailable()) {
				int typeCode = rangeReader.read(EXTENSION_TYPE_BITS);
				CertificateType certificateType = CertificateType.getTypeFromCode(typeCode);
				if (certificateType != null) {
					types.add(certificateType);
				} else {
					// client indicates a preference for an unknown certificate type
					LOG.debug("Client indicated preference for unknown {} certificate type code [{}]",
							getType().equals(ExtensionType.CLIENT_CERT_TYPE) ? "client" : "server", typeCode);
				}
			}
		} else {
			// an extension containing the negotiated certificate type is exactly 1 byte long
			int typeCode = extensionDataReader.read(EXTENSION_TYPE_BITS);
			CertificateType certificateType = CertificateType.getTypeFromCode(typeCode);
			if (certificateType != null) {
				types = new ArrayList<>(1);
				types.add(certificateType);
			} else {
				// server selected a certificate type that is unknown to this client
				LOG.debug("Server selected an unknown {} certificate type code [{}]",
						getType().equals(ExtensionType.CLIENT_CERT_TYPE) ? "client" : "server", typeCode);
				throw new IllegalArgumentException("unknown certificate type code " + typeCode + "!");
			}
		}
		certificateTypes = ListUtils.init(types);
	}

	/**
	 * Constructs a client-side certificate type extension with a list of supported
	 * certificate types.
	 * 
	 * @param type the type of the extension.
	 * @param certificateTypes the list of supported certificate types.
	 * @throws NullPointerException if certificate types is {@code null}
	 * @throws IllegalArgumentException if certificate types is empty.
	 */
	protected CertificateTypeExtension(ExtensionType type, List<CertificateType> certificateTypes) {
		super(type);
		if (certificateTypes == null) {
			throw new NullPointerException("certificate types must not be null!");
		} else if (certificateTypes.isEmpty()) {
			throw new IllegalArgumentException("certificate types data must not be empty!");
		}
		this.isClientExtension = true;
		this.certificateTypes = certificateTypes;
	}

	/**
	 * Constructs a server-side certificate type extension with a the supported
	 * certificate type.
	 * 
	 * @param type the type of the extension.
	 * @param certificateType the supported certificate type.
	 * @throws NullPointerException if certificate type is {@code null}
	 */
	protected CertificateTypeExtension(ExtensionType type, CertificateType certificateType) {
		super(type);
		if (certificateType == null) {
			throw new NullPointerException("certificate type must not be null!");
		}
		this.isClientExtension = false;
		this.certificateTypes = new ArrayList<>(1);
		this.certificateTypes.add(certificateType);
	}

	// Methods ////////////////////////////////////////////////////////
	
	public boolean isClientExtension() {
		return isClientExtension;
	}

	@Override
	public int getLength() {
		if (isClientExtension) {
			// fixed:  type (2 bytes), length (2 bytes), the list length field (1 byte)
			// each certificate type in the list uses 1 byte
			return 5 + certificateTypes.size();
		} else {
			//  type (2 bytes), length (2 bytes), the certificate type (1 byte)
			return 5;
		}
	}

	public String toString() {
		return super.toString();
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	protected void addExtensionData(DatagramWriter writer) {
		if (isClientExtension) {
			int listLength = certificateTypes.size();
			// write overall number of bytes
			// 1 byte for the number of certificate types +
			// 1 byte for each certificate type
			writer.write(1 + listLength, LENGTH_BITS);
			// write number of certificate types
			writer.write(listLength, LIST_FIELD_LENGTH_BITS);
			// write one byte for each certificate type 
			for (CertificateType type : certificateTypes) {
				writer.write(type.getCode(), EXTENSION_TYPE_BITS);
			}
		} else {
			// we assume the list contains exactly one element
			writer.write(1, LENGTH_BITS);
			writer.write(certificateTypes.get(0).getCode(), EXTENSION_TYPE_BITS);
		}
	}

	
	// Getters and Setters ////////////////////////////////////////////

	public List<CertificateType> getCertificateTypes() {
		return certificateTypes;
	}
}
