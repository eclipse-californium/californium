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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for message type
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.io.Serializable;
import java.net.InetSocketAddress;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * 
 * Alert messages convey the severity of the message (warning or fatal) and a
 * description of the alert. Alert messages with a level of fatal result in the
 * immediate termination of the connection. In this case, other connections
 * corresponding to the session may continue, but the session identifier MUST be
 * invalidated, preventing the failed session from being used to establish new
 * connections. Like other messages, alert messages are encrypted and
 * compressed, as specified by the current connection state. For further details
 * see <a href="http://tools.ietf.org/html/rfc5246#section-7.2">RFC 5246</a>.
 */
public final class AlertMessage implements DTLSMessage, Serializable {

	// CoAP-specific constants/////////////////////////////////////////
	private static final long serialVersionUID = 1L;

	private static final int BITS = 8;

	// Members ////////////////////////////////////////////////////////

	private final InetSocketAddress peerAddress;

	/** The level of the alert (warning or fatal). */
	private final AlertLevel level;

	/** The description of the alert. */
	private final AlertDescription description;

	/**
	 * The record protocol version to send.
	 * 
	 * @since 2.6
	 */
	private transient final ProtocolVersion protocolVersion;

	// Constructors ///////////////////////////////////////////////////

	protected AlertMessage() {
		this(null, null, null, null);
	}

	/**
	 * Create new instance of alert message.
	 * 
	 * @param level the alert level
	 * @param description the alert description
	 * @param peerAddress the IP address and port of the peer this message has
	 *            been received from or is to be sent to
	 * @throws NullPointerException if one of the provided parameter is
	 *             {@code null}
	 */
	public AlertMessage(AlertLevel level, AlertDescription description, InetSocketAddress peerAddress) {
		this(level, description, null, peerAddress);
	}

	/**
	 * Create new instance of alert message.
	 * 
	 * @param level the alert level
	 * @param description the alert description
	 * @param protocolVersion protocol version of record to send. Only possible
	 *            for {@link AlertDescription#PROTOCOL_VERSION} alerts!
	 * @param peerAddress the IP address and port of the peer this message has
	 *            been received from or is to be sent to
	 * @throws NullPointerException if one of the provided parameter is
	 *             {@code null}
	 * @throws IllegalArgumentException if a protocol version is provided, but
	 *             the description is not
	 *             {@link AlertDescription#PROTOCOL_VERSION}
	 * @since 2.6
	 */
	public AlertMessage(AlertLevel level, AlertDescription description, ProtocolVersion protocolVersion,
			InetSocketAddress peerAddress) {
		if (level == null) {
			throw new NullPointerException("Level must not be null");
		} else if (description == null) {
			throw new NullPointerException("Description must not be null");
		} else if (peerAddress == null) {
			throw new NullPointerException("Peer address must not be null");
		} else if (protocolVersion != null && description != AlertDescription.PROTOCOL_VERSION) {
			throw new IllegalArgumentException("Protocol version is only supported for that specific alert!");
		}
		this.peerAddress = peerAddress;
		this.level = level;
		this.description = description;
		this.protocolVersion = protocolVersion;
	}

	// Alert Level Enum ///////////////////////////////////////////////

	/**
	 * See <a href="http://tools.ietf.org/html/rfc5246#appendix-A.3">Alert
	 * Messages</a> for the listing.
	 */
	public enum AlertLevel {
		WARNING(1), FATAL(2);

		private byte code;

		private AlertLevel(int code) {
			this.code = (byte) code;
		}

		public byte getCode() {
			return code;
		}

		/**
		 * Gets the alert level for a given code.
		 * 
		 * @param code the code
		 * @return the corresponding level or <code>null</code> if no alert level exists for the given code
		 */
		public static AlertLevel getLevelByCode(int code) {
			switch (code) {
			case 1:
				return AlertLevel.WARNING;

			case 2:
				return AlertLevel.FATAL;

			default:
				return null;
			}
		}
	}

	// Alert Description Enum /////////////////////////////////////////

	/**
	 * See <a href="http://tools.ietf.org/html/rfc5246#appendix-A.3">Alert
	 * Messages</a> for the listing.
	 */
	public enum AlertDescription {

		CLOSE_NOTIFY(0, "close_notify"),
		UNEXPECTED_MESSAGE(10, "unexpected_message"),
		BAD_RECORD_MAC(20, "bad_record_mac"),
		DECRYPTION_FAILED_RESERVED(21, "decryption_failed"),
		RECORD_OVERFLOW(22, "record_overflow"),
		DECOMPRESSION_FAILURE(30, "decompression_failure"),
		HANDSHAKE_FAILURE(40, "handshake_failure"),
		NO_CERTIFICATE_RESERVED(41, "no_certificate"),
		BAD_CERTIFICATE(42, "bad_certificate"),
		UNSUPPORTED_CERTIFICATE(43, "unsupported_certificate"),
		CERTIFICATE_REVOKED(44, "certificate_revoked"),
		CERTIFICATE_EXPIRED(45, "certificate_expired"),
		CERTIFICATE_UNKNOWN(46, "certificate_unknown"),
		ILLEGAL_PARAMETER(47, "illegal_parameter"),
		UNKNOWN_CA(48, "unknown_ca"),
		ACCESS_DENIED(49, "access_denied"),
		DECODE_ERROR(50, "decode_error"),
		DECRYPT_ERROR(51, "decrypt_error"),
		EXPORT_RESTRICTION_RESERVED(60, "export_restriction"),
		PROTOCOL_VERSION(70, "protocol_version"),
		INSUFFICIENT_SECURITY(71, "insufficient_security"),
		INTERNAL_ERROR(80, "internal_error"),
		USER_CANCELED(90, "user_canceled"),
		NO_RENEGOTIATION(100, "no_negotiation"),
		UNSUPPORTED_EXTENSION(110, "unsupported_extension"),
		UNKNOWN_PSK_IDENTITY(115, "unknown_psk_identity");

		private byte code;
		private String description;

		private AlertDescription(int code, String description) {
			this.code = (byte) code;
			this.description = description;
		}

		public byte getCode() {
			return code;
		}

		public String getDescription() {
			return description;
		}

		/**
		 * Gets the alert description for a given code.
		 * 
		 * @param code the code
		 * @return the corresponding description or <code>null</code> if no alert description exists for the given code
		 */
		public static AlertDescription getDescriptionByCode(int code) {
			for (AlertDescription desc : values()) {
				if (desc.code == (byte) code) {
					return desc;
				}
			}
			return null;
		}
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public final InetSocketAddress getPeer() {
		return peerAddress;
	}

	@Override
	public ContentType getContentType() {
		return ContentType.ALERT;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("\tAlert Protocol").append(StringUtil.lineSeparator());
		sb.append("\tLevel: ").append(level).append(StringUtil.lineSeparator());
		sb.append("\tDescription: ").append(description).append(StringUtil.lineSeparator());
		if (protocolVersion != null) {
			sb.append("\tProtocol Version: ").append(protocolVersion).append(StringUtil.lineSeparator());
		}
		return sb.toString();
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public int size() {
		return (2 * BITS) / Byte.SIZE;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] toByteArray() {
		DatagramWriter writer = new DatagramWriter();

		writer.write(level.getCode(), BITS);
		writer.write(description.getCode(), BITS);

		return writer.toByteArray();
	}

	public static AlertMessage fromByteArray(final byte[] byteArray, final InetSocketAddress peerAddress) throws HandshakeException {
		DatagramReader reader = new DatagramReader(byteArray);
		byte levelCode = reader.readNextByte();
		byte descCode = reader.readNextByte();
		AlertLevel level = AlertLevel.getLevelByCode(levelCode);
		AlertDescription description = AlertDescription.getDescriptionByCode(descCode);
		if (level == null) {
			throw new HandshakeException(
					String.format("Unknown alert level code [%d]", levelCode),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR, peerAddress));
		} else if (description == null) {
			throw new HandshakeException(
					String.format("Unknown alert description code [%d]", descCode),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR, peerAddress));
		} else {
			return new AlertMessage(level, description, peerAddress);
		}
	}

	/**
	 * Get protocol version to use for the record on sending.
	 * 
	 * @return protocol version, or {@code null}, for fixed or negotiated
	 *         version.
	 */
	public ProtocolVersion getProtocolVersion() {
		return protocolVersion;
	}

	public AlertLevel getLevel() {
		return level;
	}

	public AlertDescription getDescription() {
		return description;
	}

	public boolean isFatal() {
		return AlertLevel.FATAL.equals(level);
	}
}
