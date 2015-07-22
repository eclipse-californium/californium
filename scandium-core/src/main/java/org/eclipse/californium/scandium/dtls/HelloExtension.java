/*******************************************************************************
 * Copyright (c) 2014, 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - improve toString()
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.scandium.util.DatagramWriter;


/**
 * An abstract class representing the functionality for all possible defined
 * extensions. See <a
 * href="http://tools.ietf.org/html/rfc5246#section-7.4.1.4">RFC 5246</a> for
 * the extension format.
 */
public abstract class HelloExtension {

	// DTLS-specific constants ////////////////////////////////////////

	protected static final int TYPE_BITS = 16;

	protected static final int LENGTH_BITS = 16;

	// Members ////////////////////////////////////////////////////////

	private ExtensionType type;

	// Constructors ///////////////////////////////////////////////////

	public HelloExtension(ExtensionType type) {
		this.type = type;
	}

	// Abstract methods ///////////////////////////////////////////////

	public abstract int getLength();

	// Serialization //////////////////////////////////////////////////

	public byte[] toByteArray() {
		DatagramWriter writer = new DatagramWriter();

		writer.write(type.getId(), TYPE_BITS);

		return writer.toByteArray();
	}
	
	/**
	 * De-serializes a Client or Server Hello handshake message extension from its binary
	 * representation.
	 * 
	 * The TLS spec is unspecific about how a server should handle extensions sent by a client
	 * that it does not understand. However, <a href="http://tools.ietf.org/html/rfc7250#section-4.2">
	 * Section 4.2 of RFC 7250</a> mandates that a server implementation must simply ignore
	 * extensions of type <em>client_certificate_type</em> or <em>server_certificate_type</em>
	 * if it does not support these extensions.
	 * 
	 * This (lenient) approach seems feasible for the server to follow in general when
	 * a client sends an extension of a type that the server does not know or support (yet).
	 * 
	 * @param typeCode the extension type code
	 * @param extension the serialized extension
	 * @return the object representing the extension or <code>null</code> if the extension
	 * type is not (yet) known to or supported by Scandium.
	 * @throws HandshakeException if the (supported) extension could not be de-serialized, e.g. due
	 * to erroneous encoding etc.
	 */
	public static HelloExtension fromByteArray(int typeCode, byte[] extension) throws HandshakeException {
		ExtensionType type = ExtensionType.getExtensionTypeById(typeCode);
		if (type == null) {
			return null;
		} else {
			switch (type) {
			// the currently supported extensions
			case ELLIPTIC_CURVES:
				return SupportedEllipticCurvesExtension.fromByteArray(extension);
			case EC_POINT_FORMATS:
				return SupportedPointFormatsExtension.fromByteArray(extension);
			case CLIENT_CERT_TYPE:
				return ClientCertificateTypeExtension.fromByteArray(extension);
			case SERVER_CERT_TYPE:
				return ServerCertificateTypeExtension.fromByteArray(extension);
	
			default:
				return null;
			}
		}
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("\t\t\tExtension: ").append(type).append(" (").append(type.getId()).append(")\n");
		return sb.toString();
	}
	
	final ExtensionType getType() {
		return type;
	}
	
	// Extension type Enum ////////////////////////////////////////////

	/**
	 * The possible extension types (defined in multiple documents). See <a
	 * href=
	 * "http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml"
	 * >IANA</a> for a summary.
	 */
	public enum ExtensionType {
		/** See <a href="http://www.ietf.org/rfc/rfc3546">RFC 3546</a> */
		SERVER_NAME(0, "server_name"),
		MAX_FRAGMENT_LENGTH(1, "max_fragment_length"),
		CLIENT_CERTIFICATE_URL(2, "client_certificate_url"),
		TRUSTED_CA_KEYS(3, "trusted_ca_keys"),
		TRUNCATED_HMAC(4, "truncated_hmac"),
		STATUS_REQUEST(5, "status_request"),

		/** See <a href="http://tools.ietf.org/html/rfc4681">RFC 4681</a> */
		USER_MAPPING(6, "user_mapping"),
		
		/** See <a href="http://www.iana.org/go/rfc5878">RFC 5878</a> */
		CLIENT_AUTHZ(7, "client_authz"),
		SERVER_AUTHZ(8, "server_authz"),

		/**
		 * See <a href=
		 * "http://tools.ietf.org/html/draft-ietf-tls-oob-pubkey-03#section-3.1"
		 * >TLS Out-of-Band Public Key Validation</a>
		 */
		CERT_TYPE(9, "cert_type"),

		/**
		 * See <a href="http://tools.ietf.org/html/rfc4492#section-5.1">RFC
		 * 4492</a>
		 */
		ELLIPTIC_CURVES(10, "elliptic_curves"),
		EC_POINT_FORMATS(11, "ec_point_formats"),
		
		/** See <a href="http://www.iana.org/go/rfc5054">RFC 5054</a> */
		SRP(12, "srp"),
		
		/** See <a href="http://www.iana.org/go/rfc5246">RFC 5246</a> */
		SIGNATURE_ALGORITHMS(13, "signature_algorithms"),
		
		/** See <a href="http://www.iana.org/go/rfc5764">RFC 5764</a> */
		USE_SRTP(14, "use_srtp"),
		
		/** See <a href="http://www.iana.org/go/rfc6520">RFC 6520</a> */
		HEARTBEAT(15, "heartbeat"),
		
		/** See <a href="http://www.iana.org/go/draft-friedl-tls-applayerprotoneg">draft-friedl-tls-applayerprotoneg</a> */
		APPLICATION_LAYER_PROTOCOL_NEGOTIATION(16, "application_layer_protocol_negotiation"),

		/** See <a href="http://www.iana.org/go/draft-ietf-tls-multiple-cert-status-extension-08">draft-ietf-tls-multiple-cert-status-extension-08</a> */
		STATUS_REQUEST_V2(17, "status_request_v2"),
		
		/** See <a href="http://www.iana.org/go/draft-laurie-pki-sunlight-12">draft-laurie-pki-sunlight-12</a> */
		SIGNED_CERTIFICATE_TIMESTAMP(18, "signed_certificate_timestamp"),
		
		/** See <a href="http://tools.ietf.org/html/rfc7250">RFC 7250</a> */
		CLIENT_CERT_TYPE(19, "client_certificate_type"),
		SERVER_CERT_TYPE(20, "server_certificate_type"),
		
		/** See <a href="http://www.iana.org/go/rfc7366">RFC 7366</a> **/
		ENCRYPT_THEN_MAC(22, "encrypt_then_mac"),
		
		/** See <a href="http://www.iana.org/go/rfc4507">RFC 4507</a> **/
		SESSION_TICKET_TLS(35, "SessionTicket TLS"),
		
		/** See <a href="http://www.iana.org/go/rfc5746">RFC 5746</a> **/
		RENEGOTIATION_INFO(65281, "renegotiation_info");
		

		private int id;

		private String name;

		ExtensionType(int id, String name) {
			this.id = id;
			this.name = name;
		}
		
		/**
		 * Gets an extension type by its numeric id as defined by <a href=
		 * "http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml">IANA</a>
		 * 
		 * @param id
		 *            the numeric id of the extension
		 * @return the corresponding extension type or <code>null</code> if the
		 *         given id is unsupported.
		 */
		public static ExtensionType getExtensionTypeById(int id) {
			switch (id) {
			case 0:
				return ExtensionType.SERVER_NAME;
			case 1:
				return ExtensionType.MAX_FRAGMENT_LENGTH;
			case 2:
				return ExtensionType.CLIENT_CERTIFICATE_URL;
			case 3:
				return ExtensionType.TRUSTED_CA_KEYS;
			case 4:
				return ExtensionType.TRUNCATED_HMAC;
			case 5:
				return ExtensionType.STATUS_REQUEST;
			case 6:
				return ExtensionType.USER_MAPPING;
			case 7:
				return ExtensionType.CLIENT_AUTHZ;
			case 8:
				return ExtensionType.SERVER_AUTHZ;
			case 9:
				return ExtensionType.CERT_TYPE;
			case 10:
				return ExtensionType.ELLIPTIC_CURVES;
			case 11:
				return ExtensionType.EC_POINT_FORMATS;
			case 12:
				return ExtensionType.SRP;
			case 13:
				return ExtensionType.SIGNATURE_ALGORITHMS;
			case 14:
				return ExtensionType.USE_SRTP;
			case 15:
				return ExtensionType.HEARTBEAT;
			case 16:
				return ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION;
			case 17:
				return ExtensionType.STATUS_REQUEST_V2;
			case 18:
				return ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP;
			case 19:
				return ExtensionType.CLIENT_CERT_TYPE;
			case 20:
				return ExtensionType.SERVER_CERT_TYPE;
			case 22:
				return ExtensionType.ENCRYPT_THEN_MAC;
			case 35:
				return ExtensionType.SESSION_TICKET_TLS;
			case 65281:
				return ExtensionType.RENEGOTIATION_INFO;
			default:
				return null;
			}
		}

		@Override
		public String toString() {
			return name;
		}

		public int getId() {
			return id;
		}
	}
}
