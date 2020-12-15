/*******************************************************************************
 * Copyright (c) 2016, 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - use ASN.1 DER encoding
 *                                                    directly for serialization
 *    Achim Kraus (Bosch Software Innovations GmbH) - distinguish plain and scoped
 *                                                    identity. issue #649
 *******************************************************************************/

package org.eclipse.californium.scandium.auth;

import java.security.GeneralSecurityException;
import java.security.Principal;

import org.eclipse.californium.elements.auth.PreSharedKeyIdentity;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.util.Asn1DerDecoder;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.SerializationUtil;

/**
 * A helper for serializing and deserializing principals supported by Scandium.
 */
public final class PrincipalSerializer {

	private static final int PSK_HOSTNAME_LENGTH_BITS = 16;
	private static final int PSK_IDENTITY_LENGTH_BITS = 16;

	private PrincipalSerializer() {
	}

	/**
	 * Serializes a principal to a byte array based on the plain text encoding defined in
	 * <a href="https://tools.ietf.org/html/rfc5077#section-4">RFC 5077, Section 4</a>.
	 * <p>
	 * RFC 5077 does not explicitly define support for RawPublicKey based client authentication.
	 * However, it supports the addition of arbitrary authentication mechanisms by extending
	 * the <em>ClientAuthenticationType</em> which we do as follows: 
	 * <pre>
	 * 
	 * enum {
	 *   anonymous(0),
	 *   certificate_based(1),
	 *   psk(2),
	 *   raw_public_key(255)
	 * } ClientAuthenticationType
	 * 
	 * struct {
	 *   ClientAuthenticationType client_authentication_type;
	 *   select (ClientAuthenticationType) {
	 *     case anonymous: 
	 *       struct {};
	 *     case psk:
	 *       opaque psk_identity&lt;0..2^16-1&gt;;
	 *     case certificate_based:
	 *       DER ASN.1Cert certificate_list&lt;0..2^24-1&gt;;
	 *     case raw_public_key:
	 *       DER ASN.1_subjectPublicKeyInfo&lt;1..2^24-1&gt;; // as defined in RFC 7250
	 *   };
	 * }
	 * </pre>
	 * 
	 * psk_identity may be scoped by server name indication. To distinguish
	 * scoped and plain psk_identity, the first byte in the opaque psk_identity
	 * indicates a scoped identity with 1, or a plain identity with 0.
	 * 
	 * @param principal The principal to serialize.
	 * @param writer The writer to serialize to.
	 * @throws NullPointerException if the writer is {@code null}.
	 */
	public static void serialize(final Principal principal, final DatagramWriter writer) {
		if (writer == null) {
			throw new NullPointerException("Writer must not be null");
		} else if (principal == null) {
			writer.writeByte(ClientAuthenticationType.ANONYMOUS.code);
		} else if (principal instanceof PreSharedKeyIdentity) {
			serializeIdentity((PreSharedKeyIdentity) principal, writer);
		} else if (principal instanceof RawPublicKeyIdentity) {
			serializeSubjectInfo((RawPublicKeyIdentity) principal, writer);
		} else if (principal instanceof X509CertPath) {
			serializeCertChain((X509CertPath) principal, writer);
		} else {
			throw new IllegalArgumentException("unsupported principal type: " + principal.getClass().getName());
		}
	}

	private static void serializeIdentity(final PreSharedKeyIdentity principal, final DatagramWriter writer) {
		writer.writeByte(ClientAuthenticationType.PSK.code);
		if (principal.isScopedIdentity()) {
			writer.writeByte((byte) 1); // scoped
			SerializationUtil.write(writer, principal.getVirtualHost(), PSK_HOSTNAME_LENGTH_BITS);
			SerializationUtil.write(writer, principal.getIdentity(), PSK_IDENTITY_LENGTH_BITS);
		} else {
			writer.writeByte((byte) 0); // plain
			SerializationUtil.write(writer, principal.getIdentity(), PSK_IDENTITY_LENGTH_BITS);
		}
	}

	private static void serializeSubjectInfo(final RawPublicKeyIdentity principal, final DatagramWriter writer) {
		writer.writeByte(ClientAuthenticationType.RPK.code);
		writer.writeBytes(principal.getSubjectInfo());
	}

	private static void serializeCertChain(final X509CertPath principal, final DatagramWriter writer) {
		writer.writeByte(ClientAuthenticationType.CERT.code);
		writer.writeBytes(principal.toByteArray());
	}

	/**
	 * Deserializes a principal from its byte array representation.
	 * 
	 * @param reader The reader containing the byte array.
	 * @return The principal object or {@code null} if the reader does not contain a supported principal type.
	 * @throws GeneralSecurityException if the reader contains a raw public key principal that could not be recreated.
	 * @throws IllegalArgumentException if the reader contains an unsupported ClientAuthenticationType.
	 */
	public static Principal deserialize(final DatagramReader reader) throws GeneralSecurityException {
		if (reader == null) {
			throw new NullPointerException("reader must not be null");
		}
		byte code = reader.readNextByte();
		ClientAuthenticationType type = ClientAuthenticationType.fromCode(code);
		switch(type) {
		case CERT:
			return deserializeCertChain(reader);
		case PSK:
			return deserializeIdentity(reader);
		case RPK:
			return deserializeSubjectInfo(reader);
		default:
			// ANONYMOUS
			return null;
		}
	}

	private static X509CertPath deserializeCertChain(final DatagramReader reader) {
		byte[] certificatePath = Asn1DerDecoder.readSequenceEntity(reader);
		return X509CertPath.fromBytes(certificatePath);
	}

	private static PreSharedKeyIdentity deserializeIdentity(final DatagramReader reader) {
		byte scoped = reader.readNextByte();
		if (scoped == 1) {
			String virtualHost = SerializationUtil.readString(reader, PSK_HOSTNAME_LENGTH_BITS);
			String pskIdentity = SerializationUtil.readString(reader, PSK_IDENTITY_LENGTH_BITS);
			return new PreSharedKeyIdentity(virtualHost, pskIdentity);
		} else {
			String pskIdentity = SerializationUtil.readString(reader, PSK_IDENTITY_LENGTH_BITS);
			return new PreSharedKeyIdentity(pskIdentity);
		}
	}

	private static RawPublicKeyIdentity deserializeSubjectInfo(final DatagramReader reader)
			throws GeneralSecurityException {
		byte[] subjectInfo = Asn1DerDecoder.readSequenceEntity(reader);
		return new RawPublicKeyIdentity(subjectInfo);
	}

	private enum ClientAuthenticationType {

		ANONYMOUS((byte) 0x00),
		CERT((byte) 0x01),
		PSK((byte) 0x02),
		RPK((byte) 0xff);

		private byte code;

		private ClientAuthenticationType(final byte code) {
			this.code = code;
		}

		static ClientAuthenticationType fromCode(final byte code) {
			for (ClientAuthenticationType type : values()) {
				if (type.code == code) {
					return type;
				}
			}
			throw new IllegalArgumentException("unknown ClientAuthenticationType: " + code);
		}
	}
}
