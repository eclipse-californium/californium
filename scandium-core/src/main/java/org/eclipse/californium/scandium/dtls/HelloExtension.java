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
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An abstract class representing the functionality for all possible defined
 * extensions.
 * <p>
 * See <a href="https://tools.ietf.org/html/rfc5246#section-7.4.1.4" target=
 * "_blank">RFC 5246</a> for the extension format.
 * <p>
 * In particular this class is an object representation of the
 * <em>Extension</em> struct defined in
 * <a href="https://tools.ietf.org/html/rfc5246#section-7.4.1.4" target=
 * "_blank"> TLS 1.2, Section 7.4.1.4</a>:
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
	/**
	 * The logger.
	 * 
	 * @deprecated to be removed.
	 */
	@Deprecated
	protected static final Logger LOGGER = LoggerFactory.getLogger(HelloExtension.class);

	public static final int TYPE_BITS = 16;

	public static final int LENGTH_BITS = 16;

	private final ExtensionType type;

	protected HelloExtension(final ExtensionType type) {
		if (type == null) {
			throw new NullPointerException("extension type must not be null!");
		}
		this.type = type;
	}

	/**
	 * Gets the length of this extension's corresponding <em>Extension</em>
	 * struct.
	 * <p>
	 * Note that this doesn't include the 2 bytes indicating the extension type
	 * nor the 2 bytes for the length.
	 * 
	 * @return the length in bytes
	 * @since 3.0
	 */
	protected abstract int getExtensionLength();

	/**
	 * Serializes this extension to its byte representation as specified by its
	 * respective RFC.
	 * <p>
	 * The extension code and length is already serialized.
	 * 
	 * @param writer writer to write extension to.
	 * @since 3.0
	 */
	protected abstract void writeExtensionTo(DatagramWriter writer);

	/**
	 * Gets the textual presentation of this message.
	 * 
	 * @param indent line indentation
	 * @return textual presentation
	 * @since 3.0
	 */
	public String toString(int indent) {
		StringBuilder sb = new StringBuilder();
		String indentation = StringUtil.indentation(indent);
		sb.append(indentation).append("Extension: ").append(type).append(" (").append(type.getId()).append("), ")
				.append(getExtensionLength()).append(" bytes").append(StringUtil.lineSeparator());
		return sb.toString();
	}

	@Override
	public String toString() {
		return toString(0);
	}

	final ExtensionType getType() {
		return type;
	}

	/**
	 * Gets the length of the encoding of this extension's.
	 * <p>
	 * Note this includes the 2 bytes indicating the extension type and the 2
	 * bytes for the length.
	 * 
	 * @return the encoded length in bytes
	 */
	public int getLength() {
		return ((TYPE_BITS + LENGTH_BITS) / Byte.SIZE) + getExtensionLength();
	}

	/**
	 * Write extensions.
	 * 
	 * @param writer writer to write extensions to.
	 * @since 3.0
	 */
	public void writeTo(DatagramWriter writer) {
		writer.write(getType().getId(), TYPE_BITS);
		writer.write(getExtensionLength(), LENGTH_BITS);
		writeExtensionTo(writer);
	}

	/**
	 * De-serializes a Client or Server Hello handshake message extension from
	 * its binary representation.
	 * 
	 * The TLS spec is unspecific about how a server should handle extensions
	 * sent by a client that it does not understand. However,
	 * <a href="https://tools.ietf.org/html/rfc7250#section-4.2" target=
	 * "_blank"> Section 4.2 of RFC 7250</a> mandates that a server
	 * implementation must simply ignore extensions of type
	 * <em>client_certificate_type</em> or <em>server_certificate_type</em>, if
	 * it does not support these extensions.
	 * 
	 * This (lenient) approach seems feasible for the server to follow in
	 * general when a client sends an extension of a type that the server does
	 * not know or support (yet).
	 * 
	 * @param reader the serialized extension
	 * @return the object representing the extension or {@code null}, if the
	 *         extension type is not (yet) known to or supported by Scandium.
	 * @throws HandshakeException if the (supported) extension could not be
	 *             de-serialized, e.g. due to erroneous encoding etc.
	 * @since 3.0 (removed parameter type)
	 */
	public static HelloExtension readFrom(DatagramReader reader) throws HandshakeException {
		int typeId = reader.read(TYPE_BITS);
		int extensionLength = reader.read(LENGTH_BITS);
		DatagramReader extensionDataReader = reader.createRangeReader(extensionLength);
		ExtensionType type = ExtensionType.getExtensionTypeById(typeId);
		HelloExtension extension = null;
		if (type != null) {
			switch (type) {
			// the currently supported extensions
			case ELLIPTIC_CURVES:
				extension = SupportedEllipticCurvesExtension.fromExtensionDataReader(extensionDataReader);
				break;
			case EC_POINT_FORMATS:
				extension = SupportedPointFormatsExtension.fromExtensionDataReader(extensionDataReader);
				break;
			case SIGNATURE_ALGORITHMS:
				extension = SignatureAlgorithmsExtension.fromExtensionDataReader(extensionDataReader);
				break;
			case CLIENT_CERT_TYPE:
				extension = ClientCertificateTypeExtension.fromExtensionDataReader(extensionDataReader);
				break;
			case SERVER_CERT_TYPE:
				extension = ServerCertificateTypeExtension.fromExtensionDataReader(extensionDataReader);
				break;
			case MAX_FRAGMENT_LENGTH:
				extension = MaxFragmentLengthExtension.fromExtensionDataReader(extensionDataReader);
				break;
			case SERVER_NAME:
				extension = ServerNameExtension.fromExtensionDataReader(extensionDataReader);
				break;
			case RECORD_SIZE_LIMIT:
				extension = RecordSizeLimitExtension.fromExtensionDataReader(extensionDataReader);
				break;
			case EXTENDED_MASTER_SECRET:
				extension = ExtendedMasterSecretExtension.fromExtensionDataReader(extensionDataReader);
				break;
			case CONNECTION_ID:
				extension = ConnectionIdExtension.fromExtensionDataReader(extensionDataReader, type);
				break;
			case RENEGOTIATION_INFO:
				extension = RenegotiationInfoExtension.fromExtensionDataReader(extensionDataReader);
				break;
			default:
				if (type.replacement == ExtensionType.CONNECTION_ID) {
					extension = ConnectionIdExtension.fromExtensionDataReader(extensionDataReader, type);
				}
				break;
			}
		}
		if (extension != null) {
			if (extensionDataReader.bytesAvailable()) {
				byte[] bytesLeft = extensionDataReader.readBytesLeft();
				throw new HandshakeException(String.format(
						"Too many bytes, %d left, hello extension not completely parsed! hello extension type %d",
						bytesLeft.length, typeId), new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR));
			}
		} else {
			extensionDataReader.close();
		}
		return extension;
	}

	/**
	 * The possible extension types (defined in multiple documents). See
	 * <a href=
	 * "https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml"
	 * >IANA</a> for a summary.
	 */
	public enum ExtensionType {

		// See https://tools.ietf.org/html/rfc6066
		SERVER_NAME(0, "server_name"), MAX_FRAGMENT_LENGTH(1, "max_fragment_length"), CLIENT_CERTIFICATE_URL(2,
				"client_certificate_url"), TRUSTED_CA_KEYS(3,
						"trusted_ca_keys"), TRUNCATED_HMAC(4, "truncated_hmac"), STATUS_REQUEST(5, "status_request"),

		/**
		 * See <a href="https://tools.ietf.org/html/rfc4681" target="_blank">RFC
		 * 4681</a>
		 */
		USER_MAPPING(6, "user_mapping"),

		/**
		 * See <a href="https://www.iana.org/go/rfc5878" target="_blank">RFC
		 * 5878</a>
		 */
		CLIENT_AUTHZ(7, "client_authz"), SERVER_AUTHZ(8, "server_authz"),

		/**
		 * See <a href=
		 * "https://tools.ietf.org/html/draft-ietf-tls-oob-pubkey-03#section-3.1"
		 * >TLS Out-of-Band Public Key Validation</a>
		 */
		CERT_TYPE(9, "cert_type"),

		/**
		 * See <a href="https://tools.ietf.org/html/rfc4492#section-5.1" target=
		 * "_blank">RFC 4492</a>
		 */
		ELLIPTIC_CURVES(10, "elliptic_curves"), EC_POINT_FORMATS(11, "ec_point_formats"),

		/**
		 * See <a href="https://www.iana.org/go/rfc5054" target="_blank">RFC
		 * 5054</a>
		 */
		SRP(12, "srp"),

		/** See <a href="https://www.iana.org/go/rfc5246">RFC 5246</a> */
		SIGNATURE_ALGORITHMS(13, "signature_algorithms"),

		/**
		 * See <a href="https://www.iana.org/go/rfc5764" target="_blank">RFC
		 * 5764</a>
		 */
		USE_SRTP(14, "use_srtp"),

		/**
		 * See <a href="https://www.iana.org/go/rfc6520" target="_blank">RFC
		 * 6520</a>
		 */
		HEARTBEAT(15, "heartbeat"),

		/**
		 * See
		 * <a href="https://www.iana.org/go/draft-friedl-tls-applayerprotoneg"
		 * target="_blank">draft-friedl-tls-applayerprotoneg</a>
		 */
		APPLICATION_LAYER_PROTOCOL_NEGOTIATION(16, "application_layer_protocol_negotiation"),

		/**
		 * See <a href=
		 * "https://www.iana.org/go/draft-ietf-tls-multiple-cert-status-extension-08"
		 * target="_blank">draft-ietf-tls-multiple-cert-status-extension-08</a>
		 */
		STATUS_REQUEST_V2(17, "status_request_v2"),

		/**
		 * See
		 * <a href="https://www.iana.org/go/draft-laurie-pki-sunlight-12" target
		 * ="_blank">draft-laurie-pki-sunlight-12</a>
		 */
		SIGNED_CERTIFICATE_TIMESTAMP(18, "signed_certificate_timestamp"),

		/**
		 * See <a href="https://tools.ietf.org/html/rfc7250" target="_blank">RFC
		 * 7250</a>
		 */
		CLIENT_CERT_TYPE(19, "client_certificate_type"), SERVER_CERT_TYPE(20, "server_certificate_type"),

		/**
		 * See <a href="https://www.iana.org/go/rfc7366" target="_blank">RFC
		 * 7366</a>
		 **/
		ENCRYPT_THEN_MAC(22, "encrypt_then_mac"),

		/**
		 * See <a href="https://tools.ietf.org/html/rfc7627" target="_blank">RFC
		 * 7627</a>
		 * 
		 * @since 3.0
		 **/
		EXTENDED_MASTER_SECRET(23, "extended_master_secret"),

		/**
		 * See <a href="https://tools.ietf.org/html/rfc8449" target="_blank">RFC
		 * 8449</a>
		 * 
		 * @since 2.4
		 **/
		RECORD_SIZE_LIMIT(28, "record_size_limit"),

		/**
		 * See <a href="https://www.iana.org/go/rfc4507" target="_blank">RFC
		 * 4507</a>
		 **/
		SESSION_TICKET_TLS(35, "SessionTicket TLS"),

		/**
		 * See <a href= "https://www.rfc-editor.org/rfc/rfc9146.html" target
		 * ="_blank">RFC 9146, Connection Identifier for DTLS 1.2</a> and
		 * <a href=
		 * "https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1"
		 * target="_blank">IANA TLS ExtensionType Values</a>
		 * 
		 * @since 3.0
		 **/
		CONNECTION_ID(54, "Connection ID"),

		/**
		 * See <a href= "https://www.rfc-editor.org/rfc/rfc9146.html" target
		 * ="_blank">RFC 9146, Connection Identifier for DTLS 1.2</a> and
		 * <a href=
		 * "https://mailarchive.ietf.org/arch/msg/tls/3wCyihI6Y7ZlciwcSDaQ322myYY"
		 * target="_blank">IANA code point assignment</a>
		 * 
		 * <b>Note:</b> Before version 09 of the specification, the value 53 was
		 * used for the extension along with a different calculated MAC.
		 * 
		 * <b>Note:</b> to support other, proprietary code points, just clone
		 * this, using the proprietary code points, a different description and
		 * a different name, e.g.:
		 * 
		 * <pre>
		 * CONNECTION_ID_MEDTLS(254, "Connection ID (mbedtls)", CONNECTION_ID),
		 * </pre>
		 * 
		 * @since 3.0
		 **/
		CONNECTION_ID_DEPRECATED(53, "Connection ID (deprecated)", CONNECTION_ID),

		/**
		 * See <a href="https://www.iana.org/go/rfc5746" target="_blank">RFC
		 * 5746</a>
		 **/
		RENEGOTIATION_INFO(65281, "renegotiation_info");

		private int id;
		private String name;
		private ExtensionType replacement;

		ExtensionType(int id, String name) {
			this.id = id;
			this.name = name;
		}

		ExtensionType(int id, String name, ExtensionType replacement) {
			this.id = id;
			this.name = name;
			this.replacement = replacement;
		}

		/**
		 * Gets an extension type by its numeric id as defined by <a href=
		 * "http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml"
		 * target="_blank">IANA</a>
		 * 
		 * @param id the numeric id of the extension
		 * @return the corresponding extension type or {@code null}, if the
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

		/**
		 * IANA code point.
		 * 
		 * @return code point.
		 */
		public int getId() {
			return id;
		}

		/**
		 * Get replacement type.
		 * 
		 * Only used, if code point are changing during the development of a RFC
		 * or to support early implementations.
		 * 
		 * @return replacement type, or {@code null}, if no such type exists.
		 * @since 3.0
		 */
		public ExtensionType getReplacementType() {
			return replacement;
		}
	}
}
