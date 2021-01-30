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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - improve toString()
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add support for <em>MaxFragmentLength</em> extension
 *    Kai Hudalla (Bosch Software Innovations GmbH) - improve documentation, provide peer address to subclasses 
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;


/**
 * An abstract class representing the functionality for all possible defined
 * extensions.
 * <p>
 * See <a href="http://tools.ietf.org/html/rfc5246#section-7.4.1.4">RFC 5246</a>
 * for the extension format.
 * <p>
 * In particular this class is an object representation of the <em>Extension</em>
 * struct defined in <a href="http://tools.ietf.org/html/rfc5246#section-7.4.1.4">
 * TLS 1.2, Section 7.4.1.4</a>:
 * 
 * <pre>
 * struct {
 *    ExtensionType extension_type;
 *    opaque extension_data&lt;0..2^16-1&gt;;
 * } Extension;
 * 
 * enum {
 *    signature_algorithms(13), (65535)
 * } ExtensionType;
 * </pre>
 */
public abstract class HelloExtension {

	// DTLS-specific constants ////////////////////////////////////////

	protected static final int TYPE_BITS = 16;

	public static final int LENGTH_BITS = 16;

	// Members ////////////////////////////////////////////////////////

	private final ExtensionType type;

	// Constructors ///////////////////////////////////////////////////

	protected HelloExtension(final ExtensionType type) {
		if (type == null) {
			throw new NullPointerException("extension type must not be null!");
		}
		this.type = type;
	}

	// Abstract methods ///////////////////////////////////////////////

	/**
	 * Gets the overall length of this extension's corresponding <em>Extension</em> struct.
	 * <p>
	 * Note that this includes the 2 bytes indicating the extension type.
	 * 
	 * @return the length in bytes
	 */
	public abstract int getLength();

	// Serialization //////////////////////////////////////////////////

	/**
	 * Serializes this extension to its byte representation as specified by its
	 * respective RFC.
	 * <p>
	 * This method writes this extension's 2-byte code to the result array
	 * and then hands the array over to the {@link #addExtensionData(DatagramWriter)}
	 * method in order to add the encoded extension data.
	 * 
	 * @return The byte representation.
	 */
	public final byte[] toByteArray() {
		DatagramWriter writer = new DatagramWriter();

		writer.write(type.getId(), TYPE_BITS);
		addExtensionData(writer);
		return writer.toByteArray();
	}

	/**
	 * Adds binary encoding of this extension's data.
	 * <p>
	 * <em>Note</em>: Subclasses MUST NOT write the extension's type code to the writer
	 * as this will already have been done by the {@link #toByteArray()} method.
	 * </p>
	 * 
	 * @param writer the writer to use for serialization
	 */
	protected abstract void addExtensionData(DatagramWriter writer);

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
	 * @param extensionDataReader the serialized extension
	 * @return the object representing the extension or <code>null</code> if the extension
	 * type is not (yet) known to or supported by Scandium.
	 * @throws HandshakeException if the (supported) extension could not be de-serialized, e.g. due
	 * to erroneous encoding etc.
	 */
	public static HelloExtension fromExtensionDataReader(int typeCode, DatagramReader extensionDataReader)
			throws HandshakeException {
		ExtensionType type = ExtensionType.getExtensionTypeById(typeCode);
		if (type != null) {
			switch (type) {
			// the currently supported extensions
			case ELLIPTIC_CURVES:
				return SupportedEllipticCurvesExtension.fromExtensionDataReader(extensionDataReader);
			case EC_POINT_FORMATS:
				return SupportedPointFormatsExtension.fromExtensionDataReader(extensionDataReader);
			case SIGNATURE_ALGORITHMS:
				return SignatureAlgorithmsExtension.fromExtensionDataReader(extensionDataReader);
			case CLIENT_CERT_TYPE:
				return ClientCertificateTypeExtension.fromExtensionDataReader(extensionDataReader);
			case SERVER_CERT_TYPE:
				return ServerCertificateTypeExtension.fromExtensionDataReader(extensionDataReader);
			case MAX_FRAGMENT_LENGTH:
				return MaxFragmentLengthExtension.fromExtensionDataReader(extensionDataReader);
			case SERVER_NAME:
				return ServerNameExtension.fromExtensionDataReader(extensionDataReader);
			case CONNECTION_ID:
				return ConnectionIdExtension.fromExtensionDataReader(extensionDataReader);
			case RECORD_SIZE_LIMIT:
				return RecordSizeLimitExtension.fromExtensionDataReader(extensionDataReader);
			case EXTENDED_MASTER_SECRET:
				return ExtendedMasterSecretExtension.fromExtensionDataReader(extensionDataReader);
			default:
				break;
			}
		}
		extensionDataReader.close();
		return null;
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
	 * "https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml"
	 * >IANA</a> for a summary.
	 */
	public enum ExtensionType {
		// See https://tools.ietf.org/html/rfc6066
		SERVER_NAME(0, "server_name"),
		MAX_FRAGMENT_LENGTH(1, "max_fragment_length"),
		CLIENT_CERTIFICATE_URL(2, "client_certificate_url"),
		TRUSTED_CA_KEYS(3, "trusted_ca_keys"),
		TRUNCATED_HMAC(4, "truncated_hmac"),
		STATUS_REQUEST(5, "status_request"),

		/** See <a href="https://tools.ietf.org/html/rfc4681">RFC 4681</a> */
		USER_MAPPING(6, "user_mapping"),

		/** See <a href="https://www.iana.org/go/rfc5878">RFC 5878</a> */
		CLIENT_AUTHZ(7, "client_authz"),
		SERVER_AUTHZ(8, "server_authz"),

		/**
		 * See <a href=
		 * "https://tools.ietf.org/html/draft-ietf-tls-oob-pubkey-03#section-3.1"
		 * >TLS Out-of-Band Public Key Validation</a>
		 */
		CERT_TYPE(9, "cert_type"),

		/**
		 * See <a href="https://tools.ietf.org/html/rfc4492#section-5.1">RFC
		 * 4492</a>
		 */
		ELLIPTIC_CURVES(10, "elliptic_curves"),
		EC_POINT_FORMATS(11, "ec_point_formats"),

		/** See <a href="https://www.iana.org/go/rfc5054">RFC 5054</a> */
		SRP(12, "srp"),

		/** See <a href="https://www.iana.org/go/rfc5246">RFC 5246</a> */
		SIGNATURE_ALGORITHMS(13, "signature_algorithms"),

		/** See <a href="https://www.iana.org/go/rfc5764">RFC 5764</a> */
		USE_SRTP(14, "use_srtp"),

		/** See <a href="https://www.iana.org/go/rfc6520">RFC 6520</a> */
		HEARTBEAT(15, "heartbeat"),

		/** See <a href="https://www.iana.org/go/draft-friedl-tls-applayerprotoneg">draft-friedl-tls-applayerprotoneg</a> */
		APPLICATION_LAYER_PROTOCOL_NEGOTIATION(16, "application_layer_protocol_negotiation"),

		/** See <a href="https://www.iana.org/go/draft-ietf-tls-multiple-cert-status-extension-08">draft-ietf-tls-multiple-cert-status-extension-08</a> */
		STATUS_REQUEST_V2(17, "status_request_v2"),

		/** See <a href="https://www.iana.org/go/draft-laurie-pki-sunlight-12">draft-laurie-pki-sunlight-12</a> */
		SIGNED_CERTIFICATE_TIMESTAMP(18, "signed_certificate_timestamp"),

		/** See <a href="https://tools.ietf.org/html/rfc7250">RFC 7250</a> */
		CLIENT_CERT_TYPE(19, "client_certificate_type"),
		SERVER_CERT_TYPE(20, "server_certificate_type"),

		/** See <a href="https://www.iana.org/go/rfc7366">RFC 7366</a> **/
		ENCRYPT_THEN_MAC(22, "encrypt_then_mac"),

		/**
		 * See <a href="https://tools.ietf.org/html/rfc7627">RFC 7627</a>
		 * 
		 * @since 3.0
		 **/
		EXTENDED_MASTER_SECRET(23, "extended_master_secret"),

		/**
		 * See <a href="https://tools.ietf.org/html/rfc8449">RFC 8449</a>
		 * 
		 * @since 2.4
		 **/
		RECORD_SIZE_LIMIT(28, "record_size_limit"),

		/** See <a href="https://www.iana.org/go/rfc4507">RFC 4507</a> **/
		SESSION_TICKET_TLS(35, "SessionTicket TLS"),

		/** 
		 * See <a href="https://datatracker.ietf.org/doc/draft-ietf-tls-dtls-connection-id/">Draft dtls-connection-id</a>
		 * See <a href="https://mailarchive.ietf.org/arch/msg/tls/3wCyihI6Y7ZlciwcSDaQ322myYY">IANA code point assignment</a>
		 **/
		CONNECTION_ID(53, "Connection ID"),

		/** See <a href="https://www.iana.org/go/rfc5746">RFC 5746</a> **/
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
			for (ExtensionType type : values()) {
				if (type.getId() == id) {
					return type;
				}
			}
			return null;
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
