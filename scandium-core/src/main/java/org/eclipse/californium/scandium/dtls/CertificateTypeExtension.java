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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - small improvements to serialization
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;


/**
 * This represents the Certificate Type Extension. See <a
 * href="http://tools.ietf.org/html/draft-ietf-tls-oob-pubkey-03">Draft</a> for
 * details.
 */
public abstract class CertificateTypeExtension extends HelloExtension {

	private static final Logger LOG = Logger.getLogger(CertificateTypeExtension.class.getName());
	
	// DTLS-specific constants ////////////////////////////////////////
	
	protected static final int LIST_FIELD_LENGTH_BITS = 8;
	
	protected static final int EXTENSION_TYPE_BITS = 8;

	// Members ////////////////////////////////////////////////////////

	/**
	 * Indicates whether this extension belongs to a client or a server. This
	 * has an impact upon the message format. See <a href=
	 * "http://tools.ietf.org/html/draft-ietf-tls-oob-pubkey-03#section-3.1"
	 * >CertificateTypeExtension</a> definition.
	 */
	private boolean isClientExtension;

	/**
	 * For the client: a list of certificate types the client supports, sorted
	 * by client preference.<br>
	 * For the server: the certificate selected by the server out of the
	 * client's list.
	 */
	protected List<CertificateType> certificateTypes;

	// Constructors ///////////////////////////////////////////////////
	
	/**
	 * Constructs an empty certificate type extension. If it is client-sided
	 * there is a list of supported certificate type (ordered by preference);
	 * server-side only 1 certificate type is chosen.
	 * 
	 * @param type
	 *            the type of the extension.
	 * @param isClient
	 *            whether this instance is considered the client.
	 */
	public CertificateTypeExtension(ExtensionType type, boolean isClient) {
		super(type);
		this.isClientExtension = isClient;
		this.certificateTypes = new ArrayList<CertificateType>();
	}
	
	/**
	 * Constructs a certificate type extension with a list of supported
	 * certificate types. The server only chooses 1 certificate type.
	 * 
	 * @param type
	 *            the type of the extension.
	 * @param isClient
	 *            whether this instance is considered the client.
	 * @param certificateTypes
	 *            the list of supported certificate types.
	 */
	public CertificateTypeExtension(ExtensionType type, boolean isClient, List<CertificateType> certificateTypes) {
		super(type);
		this.isClientExtension = isClient;
		this.certificateTypes = certificateTypes;
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

	// Enums //////////////////////////////////////////////////////////

	/**
	 * Certificate types as defined in the
	 * <a href="http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml">IANA registry</a>.
	 */
	public enum CertificateType {
		// values as defined by IANA TLS Certificate Types registry
		X_509(0), OPEN_PGP(1), RAW_PUBLIC_KEY(2);

		private int code;

		private CertificateType(int code) {
			this.code = code;
		}
		
		public static CertificateType getTypeFromCode(int code) {
			switch (code) {
			case 0:
				return X_509;
			case 1:
				return OPEN_PGP;
			case 2:
				return RAW_PUBLIC_KEY;

			default:
				return null;
			}
		}

		int getCode() {
			return code;
		}
	}
	
	// Getters and Setters ////////////////////////////////////////////
	
	public void addCertificateType(CertificateType certificateType) {
		if (!isClientExtension && this.certificateTypes.size() > 0) {
			// the server is only allowed to include 1 certificate type in its ServerHello
			return;
		}
		this.certificateTypes.add(certificateType);
	}

	public List<CertificateType> getCertificateTypes() {
		return certificateTypes;
	}

	protected void addCertiticateTypes(byte[] byteArray) {
		DatagramReader reader = new DatagramReader(byteArray);
		boolean containsPreferences = byteArray.length > 1;
		if (containsPreferences) {
			// an extension containing preferred certificate types is at least 2 bytes long
			int length = reader.read(LIST_FIELD_LENGTH_BITS);
			for (int i = 0; i < length; i++) {
				int typeCode = reader.read(EXTENSION_TYPE_BITS);
				CertificateType certType = CertificateType.getTypeFromCode(typeCode);
				if (certType != null) {
					certificateTypes.add(certType);
				} else {
					// client indicates a preference for an unknown certificate
					// type
					LOG.log(Level.FINER, String.format(
							"Client indicated preference for unknown %s certificate type code [%d]",
							getType().equals(ExtensionType.CLIENT_CERT_TYPE) ? "client" : "server",
							typeCode));
				}
			}
		} else {
			// an extension containing the negotiated certificate type is exactly 1 byte long
			int typeCode = reader.read(EXTENSION_TYPE_BITS);
			CertificateType certType = CertificateType.getTypeFromCode(typeCode);
			if (certType != null) {
				certificateTypes.add(certType);
			} else {
				// server selected a certificate type that is unknown to this
				// client
				LOG.log(Level.FINER, String.format(
						"Server selected an unknown %s certificate type code [%d]",
						getType().equals(ExtensionType.CLIENT_CERT_TYPE) ? "client" : "server",
						typeCode));
			}
		}
	}
}
