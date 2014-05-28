/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;


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
public class AlertMessage implements DTLSMessage {

	// CoAP-specific constants/////////////////////////////////////////

	private static final int BITS = 8;

	// Members ////////////////////////////////////////////////////////

	/** The level of the alert (warning or fatal). */
	private AlertLevel level;

	/** The description of the alert. */
	private AlertDescription description;

	// Constructors ///////////////////////////////////////////////////

	/**
	 * 
	 * @param level
	 *            the alert level.
	 * @param description
	 *            the alert description.
	 */
	public AlertMessage(AlertLevel level, AlertDescription description) {
		this.level = level;
		this.description = description;
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

		CLOSE_NOTIFY(0),
		UNEXPECTED_MESSAGE(10),
		BAD_RECORD_MAC(20),
		DECRYPTION_FAILED_RESERVED(21),
		RECORD_OVERFLOW(22),
		DECOMPRESSION_FAILURE(30),
		HANDSHAKE_FAILURE(40),
		NO_CERTIFICATE_RESERVED(41),
		BAD_CERTIFICATE(42),
		UNSUPPORTED_CERTIFICATE(43),
		CERTIFICATE_REVOKED(44),
		CERTIFICATE_EXPIRED(45),
		CERTIFICATE_UNKNOWN(46),
		ILLEGAL_PARAMETER(47),
		UNKNOWN_CA(48),
		ACCESS_DENIED(49),
		DECODE_ERROR(50),
		DECRYPT_ERROR(51),
		EXPORT_RESTRICTION_RESERVED(60),
		PROTOCOL_VERSION(70),
		INSUFFICIENT_SECURITY(71),
		INTERNAL_ERROR(80),
		USER_CANCELED(90),
		NO_RENEGOTIATION(100),
		UNSUPPORTED_EXTENSION(110);

		private byte code;

		private AlertDescription(int code) {
			this.code = (byte) code;
		}

		public byte getCode() {
			return code;
		}

		public static AlertDescription getDescriptionByCode(int code) {
			switch (code) {
			case 0:
				return AlertDescription.CLOSE_NOTIFY;
			case 10:
				return AlertDescription.UNEXPECTED_MESSAGE;
			case 20:
				return AlertDescription.BAD_RECORD_MAC;
			case 21:
				return AlertDescription.DECRYPTION_FAILED_RESERVED;
			case 22:
				return AlertDescription.RECORD_OVERFLOW;
			case 30:
				return AlertDescription.DECOMPRESSION_FAILURE;
			case 40:
				return AlertDescription.HANDSHAKE_FAILURE;
			case 41:
				return AlertDescription.NO_CERTIFICATE_RESERVED;
			case 42:
				return AlertDescription.BAD_CERTIFICATE;
			case 43:
				return AlertDescription.UNSUPPORTED_CERTIFICATE;
			case 44:
				return AlertDescription.CERTIFICATE_REVOKED;
			case 45:
				return AlertDescription.CERTIFICATE_EXPIRED;
			case 46:
				return AlertDescription.CERTIFICATE_UNKNOWN;
			case 47:
				return AlertDescription.ILLEGAL_PARAMETER;
			case 48:
				return AlertDescription.UNKNOWN_CA;
			case 49:
				return AlertDescription.ACCESS_DENIED;
			case 50:
				return AlertDescription.DECODE_ERROR;
			case 51:
				return AlertDescription.DECRYPT_ERROR;
			case 60:
				return AlertDescription.EXPORT_RESTRICTION_RESERVED;
			case 70:
				return AlertDescription.PROTOCOL_VERSION;
			case 71:
				return AlertDescription.INSUFFICIENT_SECURITY;
			case 80:
				return AlertDescription.INTERNAL_ERROR;
			case 90:
				return AlertDescription.USER_CANCELED;
			case 100:
				return AlertDescription.NO_RENEGOTIATION;
			case 110:
				return AlertDescription.UNSUPPORTED_EXTENSION;
			default:
				return null;
			}
		}

		static String alertDescription(AlertDescription description) {
			switch (description) {

			case CLOSE_NOTIFY:
				return "close_notify";
			case UNEXPECTED_MESSAGE:
				return "unexpected_message";
			case BAD_RECORD_MAC:
				return "bad_record_mac";
			case DECRYPTION_FAILED_RESERVED:
				return "decryption_failed";
			case RECORD_OVERFLOW:
				return "record_overflow";
			case DECOMPRESSION_FAILURE:
				return "decompression_failure";
			case HANDSHAKE_FAILURE:
				return "handshake_failure";
			case NO_CERTIFICATE_RESERVED:
				return "no_certificate";
			case BAD_CERTIFICATE:
				return "bad_certificate";
			case UNSUPPORTED_CERTIFICATE:
				return "unsupported_certificate";
			case CERTIFICATE_REVOKED:
				return "certificate_revoked";
			case CERTIFICATE_EXPIRED:
				return "certificate_expired";
			case CERTIFICATE_UNKNOWN:
				return "certificate_unknown";
			case ILLEGAL_PARAMETER:
				return "illegal_parameter";
			case UNKNOWN_CA:
				return "unknown_ca";
			case ACCESS_DENIED:
				return "access_denied";
			case DECODE_ERROR:
				return "decode_error";
			case DECRYPT_ERROR:
				return "decrypt_error";
			case EXPORT_RESTRICTION_RESERVED:
				return "export_restriction";
			case PROTOCOL_VERSION:
				return "protocol_version";
			case INSUFFICIENT_SECURITY:
				return "insufficient_security";
			case INTERNAL_ERROR:
				return "internal_error";
			case USER_CANCELED:
				return "user_canceled";
			case NO_RENEGOTIATION:
				return "no_negotiation";
			case UNSUPPORTED_EXTENSION:
				return "unsupported_extension";
			default:
				return "<UNKNOWN ALERT: " + (description.getCode() & 0x0ff) + ">";
			}
		}
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("\tAlert Protocol\n");
		sb.append("\tLevel: " + level.toString() + "\n");
		sb.append("\tDescription: " + description.toString() + " \n");

		return sb.toString();
	}

	// Serialization //////////////////////////////////////////////////

	// @Override
	public byte[] toByteArray() {
		DatagramWriter writer = new DatagramWriter();

		writer.write(level.getCode(), BITS);
		writer.write(description.getCode(), BITS);

		return writer.toByteArray();
	}

	public static DTLSMessage fromByteArray(byte[] byteArray) {
		DatagramReader reader = new DatagramReader(byteArray);

		int level = reader.read(BITS);
		int description = reader.read(BITS);

		return new AlertMessage(AlertLevel.getLevelByCode(level), AlertDescription.getDescriptionByCode(description));
	}

	public AlertLevel getLevel() {
		return level;
	}

	public AlertDescription getDescription() {
		return description;
	}

}
