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
import java.util.Collections;
import java.util.List;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.util.ListUtils;

/**
 * This represents the Certificate Type Extension. See
 * <a href="https://tools.ietf.org/html/rfc7250" target="_blank">RFC 7250</a>
 * for details.
 */
public abstract class CertificateTypeExtension extends HelloExtension {

	private static final Logger LOG = LoggerFactory.getLogger(CertificateTypeExtension.class);

	protected static final int LIST_FIELD_LENGTH_BITS = 8;

	protected static final int EXTENSION_TYPE_BITS = 8;

	/**
	 * Empty list of certificate types.
	 * 
	 * @since 3.0
	 */
	public static final List<CertificateType> EMPTY = Collections.emptyList();
	/**
	 * List of default certificate types (x509).
	 * 
	 * @since 3.0
	 */
	public static final List<CertificateType> DEFAULT_X509 = asList(CertificateType.X_509);

	/**
	 * Indicates whether this extension belongs to a client or a server. This
	 * has an impact upon the message format. See
	 * <a href= "http://tools.ietf.org/html/rfc7250#section-3">
	 * CertificateTypeExtension</a> figure 4, definition.
	 */
	private final boolean isClientExtension;

	/**
	 * For the client: a list of certificate types the client supports, sorted
	 * by client preference.<br>
	 * For the server: the certificate selected by the server out of the
	 * client's list.
	 */
	protected final List<CertificateType> certificateTypes;

	/**
	 * Constructs a certificate type extension with a list of supported
	 * certificate types, or a selected certificate type chosen by the server.
	 * 
	 * @param type the type of the extension.
	 * @param extensionDataReader the list of supported certificate types or the
	 *            selected certificate type encoded in bytes.
	 * @throws NullPointerException if extension data is {@code null}
	 * @throws IllegalArgumentException if extension data is empty or no
	 *             certificate type is contained.
	 * @since 3.0 check for at least one certificate type
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
					// client indicates a preference for an unknown certificate
					// type
					LOG.debug("Client indicated preference for unknown {} certificate type code [{}]",
							getType().equals(ExtensionType.CLIENT_CERT_TYPE) ? "client" : "server", typeCode);
				}
			}
			if (types.isEmpty()) {
				throw new IllegalArgumentException("Empyt client certificate types!");
			}
		} else {
			// an extension containing the negotiated certificate type is
			// exactly 1 byte long
			int typeCode = extensionDataReader.read(EXTENSION_TYPE_BITS);
			CertificateType certificateType = CertificateType.getTypeFromCode(typeCode);
			if (certificateType != null) {
				types = asList(certificateType);
			} else {
				// server selected a certificate type that is unknown to this
				// client
				LOG.debug("Server selected an unknown {} certificate type code [{}]",
						getType().equals(ExtensionType.CLIENT_CERT_TYPE) ? "client" : "server", typeCode);
				throw new IllegalArgumentException("unknown certificate type code " + typeCode + "!");
			}
		}
		certificateTypes = ListUtils.init(types);
	}

	/**
	 * Constructs a client-side certificate type extension with a list of
	 * supported certificate types.
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
		this.certificateTypes = asList(certificateType);
	}

	public boolean isClientExtension() {
		return isClientExtension;
	}

	/**
	 * Get list of supported certificate types.
	 * 
	 * The list contains at least one certificate type.
	 * 
	 * @return list of supported certificate types
	 */
	public List<CertificateType> getCertificateTypes() {
		return certificateTypes;
	}

	/**
	 * Get certificate type.
	 * 
	 * @return certificate type (head of list)
	 * @since 3.0
	 */
	public CertificateType getCertificateType() {
		return certificateTypes.get(0);
	}

	/**
	 * Checks, if certificate type is contained in the list.
	 * 
	 * @param type certificate type to check
	 * @return {@code true}, if contained, {@code false}, if not
	 * @since 3.0
	 */
	public boolean contains(CertificateType type) {
		return certificateTypes.contains(type);
	}

	/**
	 * Get list with common certificate types.
	 * 
	 * @param supportedCertificateTypes list of supported certificate types
	 * @return list of certificate types, which are included in this extension
	 *         and in the provided list. The order is defined by the order in
	 *         this extension
	 * @since 3.0
	 */
	public List<CertificateType> getCommonCertificateTypes(List<CertificateType> supportedCertificateTypes) {
		List<CertificateType> common = new ArrayList<>();
		for (CertificateType certType : certificateTypes) {
			if (supportedCertificateTypes.contains(certType)) {
				common.add(certType);
			}
		}
		return common;
	}

	public String toString(int indent, String side) {
		StringBuilder sb = new StringBuilder(super.toString(indent));
		String indentation = StringUtil.indentation(indent + 1);
		if (isClientExtension()) {
			sb.append(indentation).append(side).append(" certificate types: (").append(getCertificateTypes().size())
					.append(" types)").append(StringUtil.lineSeparator());
			String indentation2 = StringUtil.indentation(indent + 2);
			for (CertificateType type : getCertificateTypes()) {
				sb.append(indentation2).append(side).append(" certificate type: ").append(type)
						.append(StringUtil.lineSeparator());
			}
		} else {
			sb.append(indentation).append(side).append(" certificate type: ").append(getCertificateType())
					.append(StringUtil.lineSeparator());
		}

		return sb.toString();
	}

	@Override
	protected int getExtensionLength() {
		if (isClientExtension) {
			// fixed: the list length field (1 byte)
			// each certificate type in the list uses 1 byte
			return 1 + certificateTypes.size();
		} else {
			// fixed: the certificate type (1 byte)
			return 1;
		}
	}

	@Override
	protected void writeExtensionTo(DatagramWriter writer) {
		if (isClientExtension) {
			// write number of certificate types
			writer.write(certificateTypes.size(), LIST_FIELD_LENGTH_BITS);
			// write one byte for each certificate type
			for (CertificateType type : certificateTypes) {
				writer.write(type.getCode(), EXTENSION_TYPE_BITS);
			}
		} else {
			// we assume the list contains exactly one element
			writer.write(certificateTypes.get(0).getCode(), EXTENSION_TYPE_BITS);
		}
	}

	/**
	 * Get certificate type as list.
	 * 
	 * @param certificateType certificate type
	 * @return list of certificate types with this certificate type
	 * @since 3.0
	 */
	private static List<CertificateType> asList(CertificateType certificateType) {
		List<CertificateType> certificateTypes = new ArrayList<>(1);
		certificateTypes.add(certificateType);
		return certificateTypes;
	}
}
